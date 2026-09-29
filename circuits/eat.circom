pragma circom 2.2.0;
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template Fold(n, domain) {
    signal input values[n];
    signal output out;
    component h[n];
    for (var i=0; i<n; i++) {
        h[i] = Poseidon(2);
        if (i==0) h[i].inputs[0] <== domain;
        else h[i].inputs[0] <== h[i-1].out;
        h[i].inputs[1] <== values[i];
    }
    out <== h[n-1].out;
}

template Path(depth) {
    signal input leaf;
    signal input siblings[depth];
    signal input bits[depth];
    signal output root;
    signal nodes[depth+1];
    component h[depth];
    nodes[0] <== leaf;
    for (var i=0; i<depth; i++) {
        bits[i]*(bits[i]-1) === 0;
        h[i] = Poseidon(2);
        h[i].inputs[0] <== nodes[i] + bits[i]*(siblings[i]-nodes[i]);
        h[i].inputs[1] <== siblings[i] + bits[i]*(nodes[i]-siblings[i]);
        nodes[i+1] <== h[i].out;
    }
    root <== nodes[depth];
}

template EAT(depth) {
    signal input version; signal input epoch;
    signal input bondRoot; signal input stateRoot;
    signal input bond; signal input cipherHash; signal input commitment;
    signal input nullifier; signal input quota; signal input minimum;
    signal input resourceGas;
    signal input secret; signal input deposit; signal input slot;
    signal input bondSiblings[depth]; signal input bondBits[depth];
    signal input stateSiblings[depth]; signal input stateBits[depth];
    signal input balance; signal input referenceNonce;
    // from, to, nonce, value, gasLimit, maxFee, rLo, rHi, sLo, sHi, v
    signal input tx[11]; signal input opening;

    component pseudonym = Fold(1, 10);
    pseudonym.values[0] <== secret; pseudonym.out === bond;
    component bl = Fold(4, 20);
    bl.values[0] <== bond; bl.values[1] <== version;
    bl.values[2] <== epoch; bl.values[3] <== deposit;
    component bp = Path(depth);
    bp.leaf <== bl.out;
    component sp = Path(depth);
    for (var i=0; i<depth; i++) {
        bp.siblings[i] <== bondSiblings[i]; bp.bits[i] <== bondBits[i];
        sp.siblings[i] <== stateSiblings[i]; sp.bits[i] <== stateBits[i];
    }
    bp.root === bondRoot;
    component sl = Fold(3, 30);
    sl.values[0] <== tx[0]; sl.values[1] <== balance;
    sl.values[2] <== referenceNonce;
    sp.leaf <== sl.out; sp.root === stateRoot;

    component amountBits = Num2Bits(128); amountBits.in <== deposit;
    component minimumBits = Num2Bits(128); minimumBits.in <== minimum;
    component amountCheck = GreaterEqThan(128);
    amountCheck.in[0] <== deposit; amountCheck.in[1] <== minimum;
    amountCheck.out === 1;
    component quotaBits = Num2Bits(32); quotaBits.in <== quota;
    component slotBits = Num2Bits(32); slotBits.in <== slot;
    component slotCheck = LessThan(32);
    slotCheck.in[0] <== slot; slotCheck.in[1] <== quota; slotCheck.out === 1;
    component nf = Fold(4, 40);
    nf.values[0] <== secret; nf.values[1] <== version;
    nf.values[2] <== epoch; nf.values[3] <== slot;
    nf.out === nullifier;

    var widths[11] = [160,160,32,64,32,64,128,128,128,128,8];
    component ranges[11];
    for (var j=0; j<11; j++) {
        ranges[j] = Num2Bits(widths[j]); ranges[j].in <== tx[j];
    }
    component balanceBits = Num2Bits(128); balanceBits.in <== balance;
    component nonceBits = Num2Bits(32); nonceBits.in <== referenceNonce;
    tx[2] === referenceNonce;
    resourceGas === tx[4];
    signal cost; cost <== tx[3] + tx[4]*tx[5];
    component funded = GreaterEqThan(128);
    funded.in[0] <== balance; funded.in[1] <== cost; funded.out === 1;
    component td = Fold(11, 50);
    for (var t=0; t<11; t++) td.values[t] <== tx[t];
    component cm = Fold(3, 60);
    cm.values[0] <== td.out; cm.values[1] <== opening;
    cm.values[2] <== cipherHash; cm.out === commitment;
}
component main {public [version,epoch,bondRoot,stateRoot,bond,cipherHash,commitment,nullifier,quota,minimum,resourceGas]} = EAT(4);
