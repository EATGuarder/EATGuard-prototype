// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IEATVerifier {
    function verifyProof(uint[2] calldata a,uint[2][2] calldata b,uint[2] calldata c,uint[11] calldata x) external view returns(bool);
}
interface IPoseidon { function poseidon(uint[2] calldata input) external pure returns(uint); }

library EG {
    uint internal constant FIELD=21888242871839275222246405745257275088548364400416034343698204186575808495617;
    struct Ticket { bytes cipher; uint[11] x; uint[2] a; uint[2][2] b; uint[2] c; }
    struct Payload { uint[11] fields; uint opening; }
    struct Evidence {
        bytes raw; uint index; bytes32[] path;
        uint earlierId; bytes earlierRaw; uint earlierIndex; bytes32[] earlierPath;
        bytes message; bytes certificate;
    }
    function recover(bytes32 digest,bytes memory sig) internal pure returns(address) {
        if(sig.length!=65) return address(0);
        bytes32 r; bytes32 s; uint8 v;
        assembly { r:=mload(add(sig,32)) s:=mload(add(sig,64)) v:=byte(0,mload(add(sig,96))) }
        if(v!=27 && v!=28) return address(0);
        if(uint(s)>0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0) return address(0);
        return ecrecover(digest,v,r,s);
    }
}

// Each instance uses one frozen epoch and state snapshot.
contract EATGuard {
    enum State { MISSING, PENDING, ADMISSION_FINAL, FINALIZED, REJECTED }
    enum Fault { ADMISSION_FAULT, STATIC_TX_FAULT }
    enum Reason { MALFORMED_EAT, INVALID_CONTEXT, BAD_PUBLIC_BINDING, DUPLICATE_NULLIFIER, INVALID_EAT_PROOF, PAYLOAD_ENCODING, PAYLOAD_BINDING, PDEF_SIGNATURE }
    struct Config {
        uint version; uint epoch; uint bondRoot; uint stateRoot;
        uint quota; uint deltaU; uint deltaB; uint rewardBps;
        uint epochEnd; uint admissionWindow; uint staticWindow;
        uint maxBatch; uint maxTicket; address tdn;
    }
    struct Batch { bytes32 root; address builder; uint n; uint committed; uint admissionEnd; uint staticEnd; State state; bool reserved; }
    struct Bond { address owner; uint balance; }
    Config public policy;
    IEATVerifier public immutable verifier;
    IPoseidon public immutable poseidon;
    bool public immutable senderSlashing;
    address public immutable snapshotPublisher;
    bool public frozen;
    uint public count;
    uint public totalBurned;
    uint public totalRewards;
    mapping(uint=>Batch) public batches;
    mapping(uint=>Bond) public bonds;
    mapping(address=>uint) public builderBalance;
    mapping(address=>uint) public builderReserved;
    mapping(bytes32=>bool) public usedReports;
    mapping(address=>uint) public reporterRewards;
    address payable constant BURN=payable(address(0xdead));
    event Committed(uint indexed batchId,address indexed builder,bytes32 root,uint n);
    event Penalized(uint indexed batchId,uint indexed fault,uint indexed index,uint reason,address liable,uint penalty,uint reward);

    constructor(Config memory cfg,address vk,address hashContract,bool slashSender) {
        require(cfg.quota>0 && cfg.deltaU>0 && cfg.deltaB>0 && cfg.rewardBps<=10000);
        require(cfg.maxBatch>0 && cfg.maxBatch<=128 && cfg.admissionWindow>0 && cfg.staticWindow>0);
        require(cfg.tdn!=address(0) && cfg.epochEnd>block.timestamp);
        policy=cfg; verifier=IEATVerifier(vk); poseidon=IPoseidon(hashContract); senderSlashing=slashSender; snapshotPublisher=msg.sender;
    }
    function activateBond(uint pseudonym) external payable {
        require(!frozen && block.timestamp<=policy.epochEnd && bonds[pseudonym].owner==address(0),"activation");
        require(msg.value>=policy.quota*policy.deltaU,"funding");
        bonds[pseudonym]=Bond(msg.sender,msg.value);
    }
    function fundBuilder() external payable { builderBalance[msg.sender]+=msg.value; }
    function freeze() external { require(msg.sender==snapshotPublisher && !frozen,"freeze"); frozen=true; }
    function withdrawBuilder(uint amount) external {
        require(builderBalance[msg.sender]-builderReserved[msg.sender]>=amount,"reserved");
        builderBalance[msg.sender]-=amount; _pay(payable(msg.sender),amount);
    }
    function withdrawBond(uint pseudonym) external {
        Bond storage b=bonds[pseudonym]; require(b.owner==msg.sender,"owner");
        require(block.timestamp>policy.epochEnd+policy.admissionWindow+policy.staticWindow,"horizon");
        uint amount=b.balance; b.balance=0; _pay(payable(msg.sender),amount);
    }
    function commit(bytes32 root,uint n) external returns(uint id) {
        require(frozen && block.timestamp<=policy.epochEnd && n>0 && n<=policy.maxBatch && root!=bytes32(0),"header");
        require(builderBalance[msg.sender]-builderReserved[msg.sender]>=policy.deltaB,"builder funding");
        builderReserved[msg.sender]+=policy.deltaB;
        id=++count;
        batches[id]=Batch(root,msg.sender,n,block.timestamp,block.timestamp+policy.admissionWindow,block.timestamp+policy.admissionWindow+policy.staticWindow,State.PENDING,true);
        emit Committed(id,msg.sender,root,n);
    }
    function status(uint id) public view returns(State) {
        Batch storage b=batches[id];
        if(b.state!=State.PENDING && b.state!=State.ADMISSION_FINAL) return b.state;
        if(block.timestamp>b.staticEnd) return State.FINALIZED;
        if(block.timestamp>b.admissionEnd) return State.ADMISSION_FINAL;
        return State.PENDING;
    }
    function settle(uint id) public {
        Batch storage b=batches[id]; b.state=status(id);
        if(b.reserved && b.state!=State.PENDING) {
            builderReserved[b.builder]-=policy.deltaB; b.reserved=false;
        }
    }
    function reportFault(uint id,Fault fault,Reason reason,bytes calldata encoded) external {
        settle(id);
        Batch storage b=batches[id];
        EG.Evidence memory e=abi.decode(encoded,(EG.Evidence));
        _member(id,e.raw,e.index,e.path);
        bytes32 rid=keccak256(abi.encode(id,fault,fault==Fault.ADMISSION_FAULT ? 0 : e.index));
        require(!usedReports[rid],"used report");
        uint amount; address liable;
        if(fault==Fault.ADMISSION_FAULT) {
            require(b.state==State.PENDING && uint(reason)<=uint(Reason.INVALID_EAT_PROOF),"admission window/reason");
            require(_admissionFault(id,reason,e),"no admission fault");
            usedReports[rid]=true; b.state=State.REJECTED;
            amount=policy.deltaB; liable=b.builder;
            builderBalance[liable]-=amount;
            if(b.reserved) { builderReserved[liable]-=amount; b.reserved=false; }
        } else {
            require(senderSlashing && b.state==State.ADMISSION_FINAL && uint(reason)>=uint(Reason.PAYLOAD_ENCODING),"static window/reason");
            (bool ok,EG.Ticket memory t)=_ticket(e.raw);
            require(ok && _context(t) && _binding(t) && _proof(t),"unauthorized ticket");
            require(EG.recover(certificateDigest(id,e.index,t.x[5],e.message),e.certificate)==policy.tdn,"certificate");
            require(_staticFault(t,reason,e.message),"no static fault");
            usedReports[rid]=true;
            amount=policy.deltaU; Bond storage bond=bonds[t.x[4]]; liable=bond.owner;
            require(liable!=address(0) && bond.balance>=amount,"sender funding");
            bond.balance-=amount;
        }
        uint reward=amount*policy.rewardBps/10000;
        totalRewards+=reward; totalBurned+=amount-reward; reporterRewards[msg.sender]+=reward;
        _pay(payable(msg.sender),reward); _pay(BURN,amount-reward);
        emit Penalized(id,uint(fault),e.index,uint(reason),liable,amount,reward);
    }
    function _admissionFault(uint id,Reason reason,EG.Evidence memory e) internal view returns(bool) {
        (bool ok,EG.Ticket memory t)=_ticket(e.raw);
        if(reason==Reason.MALFORMED_EAT) return !ok;
        require(ok,"malformed target");
        if(reason==Reason.INVALID_CONTEXT) return !_context(t);
        if(reason==Reason.BAD_PUBLIC_BINDING) return !_binding(t);
        if(reason==Reason.INVALID_EAT_PROOF) return !_proof(t);
        require(e.earlierId>0 && (e.earlierId<id || (e.earlierId==id && e.earlierIndex<e.index)),"order");
        require(status(e.earlierId)!=State.REJECTED,"rejected predecessor");
        _member(e.earlierId,e.earlierRaw,e.earlierIndex,e.earlierPath);
        (bool earlierOK,EG.Ticket memory old)=_ticket(e.earlierRaw);
        require(earlierOK && _context(old) && _binding(old) && _proof(old),"invalid predecessor");
        return t.x[7]==old.x[7] && t.x[0]==old.x[0] && t.x[1]==old.x[1];
    }
    function decodeTicket(bytes calldata raw) external pure returns(EG.Ticket memory t) {
        t=abi.decode(raw,(EG.Ticket)); require(keccak256(raw)==keccak256(abi.encode(t)),"canonical ticket");
    }
    function _ticket(bytes memory raw) internal view returns(bool ok,EG.Ticket memory t) {
        if(raw.length>policy.maxTicket) return(false,t);
        try this.decodeTicket(raw) returns(EG.Ticket memory decoded) { return(true,decoded); }
        catch { return(false,t); }
    }
    function _context(EG.Ticket memory t) internal view returns(bool) {
        Config memory p=policy;
        return frozen && bonds[t.x[4]].owner!=address(0) && t.x[0]==p.version && t.x[1]==p.epoch && t.x[2]==p.bondRoot && t.x[3]==p.stateRoot && t.x[8]==p.quota && t.x[9]==p.quota*p.deltaU && t.x[10]>0 && t.x[10]<=30_000_000;
    }
    function _binding(EG.Ticket memory t) internal pure returns(bool) {
        return t.x[5]==uint(keccak256(abi.encode("EATGuard/cipher/v1",t.cipher)))%EG.FIELD;
    }
    function _proof(EG.Ticket memory t) internal view returns(bool) {
        try verifier.verifyProof(t.a,t.b,t.c,t.x) returns(bool ok) {return ok;} catch {return false;}
    }
    function validTicket(bytes calldata raw) external view returns(bool) {
        (bool ok,EG.Ticket memory t)=_ticket(raw); return ok && _context(t) && _binding(t) && _proof(t);
    }
    function _member(uint id,bytes memory raw,uint index,bytes32[] memory path) internal view {
        Batch storage b=batches[id]; require(b.state!=State.MISSING && index<b.n,"position");
        uint width=1; uint depth;
        while(width<b.n) {width*=2; depth++;}
        require(path.length==depth,"path depth");
        bytes32 node=keccak256(abi.encode("EATGuard/leaf/v1",id,index,raw));
        for(uint d;d<depth;d++) {
            node=(index & (uint(1)<<d))==0 ? keccak256(abi.encodePacked(node,path[d])) : keccak256(abi.encodePacked(path[d],node));
        }
        require(node==b.root,"membership");
    }
    function certificateDigest(uint id,uint index,uint h,bytes memory message) public view returns(bytes32) {
        return keccak256(abi.encode("EATGuard/TDN/v1",block.chainid,address(this),id,index,h,keccak256(message)));
    }
    function decodePayload(bytes calldata message) external pure returns(EG.Payload memory p) {
        require(message.length==384,"payload length"); p=abi.decode(message,(EG.Payload));
        uint[11] memory widths=[uint(160),160,32,64,32,64,128,128,128,128,8];
        for(uint j;j<11;j++) require(p.fields[j]<(uint(1)<<widths[j]),"payload range");
        require(p.opening<EG.FIELD,"opening");
    }
    function _staticFault(EG.Ticket memory t,Reason reason,bytes memory message) internal view returns(bool) {
        EG.Payload memory p;
        try this.decodePayload(message) returns(EG.Payload memory parsed) {p=parsed;}
        catch {return reason==Reason.PAYLOAD_ENCODING;}
        if(reason==Reason.PAYLOAD_ENCODING) return false;
        uint digest=50;
        for(uint j;j<11;j++) digest=poseidon.poseidon([digest,p.fields[j]]);
        uint cm=poseidon.poseidon([uint(60),digest]);
        cm=poseidon.poseidon([cm,p.opening]); cm=poseidon.poseidon([cm,t.x[5]]);
        if(reason==Reason.PAYLOAD_BINDING) return cm!=t.x[6];
        require(cm==t.x[6],"payload binding prerequisite");
        bytes32 txHash=keccak256(abi.encode("EATGuard/transfer/v1",block.chainid,p.fields[0],p.fields[1],p.fields[2],p.fields[3],p.fields[4],p.fields[5]));
        bytes32 r=bytes32(p.fields[6]+(p.fields[7]<<128));
        bytes32 s=bytes32(p.fields[8]+(p.fields[9]<<128));
        address signer=EG.recover(txHash,abi.encodePacked(r,s,uint8(p.fields[10])));
        return signer==address(0) || signer!=address(uint160(p.fields[0]));
    }
    function _pay(address payable recipient,uint amount) internal { (bool ok,)=recipient.call{value:amount}(""); require(ok,"payment"); }
}
