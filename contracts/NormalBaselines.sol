// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import "EATGuard.sol";

contract BasicEM {
    mapping(uint=>bytes32) public roots;
    uint public count;
    function commit(bytes32 root,uint n) external {
        require(n>0 && n<=128 && root!=bytes32(0)); roots[++count]=root;
    }
}

contract OnChainEAT {
    EATGuard public immutable rules;
    mapping(uint=>bool) public used;
    mapping(uint=>bytes32) public roots;
    uint public count;
    constructor(address guard) {rules=EATGuard(guard);}
    function submitTicket(bytes calldata ticket) external {
        require(rules.validTicket(ticket),"invalid EAT");
        EG.Ticket memory t=rules.decodeTicket(ticket);
        require(!used[t.x[7]],"duplicate"); used[t.x[7]]=true;
    }
    function commit(bytes32 root,uint n) external {
        require(n>0 && n<=128 && root!=bytes32(0));
        roots[++count]=root;
    }
}
