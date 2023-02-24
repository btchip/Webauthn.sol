const { expect } = require("chai");
const crypto = require("crypto");

function derToRS(der) {
  var offset = 3;
  var dataOffset;

  if (der[offset] == 0x21) {
    dataOffset = offset + 2;
  }
  else {
    dataOffset = offset + 1;
  }
  const r = der.slice(dataOffset, dataOffset + 32);
  offset = offset + der[offset] + 1 + 1
  if (der[offset] == 0x21) {
    dataOffset = offset + 2;
  }
  else {
    dataOffset = offset + 1;
  }
  const s = der.slice(dataOffset, dataOffset + 32);
  return [ r, s ]
}

describe("Webauthn", function() {
  it("Check message", async function() {
    const Webauthn = await ethers.getContractFactory("Webauthn");
    const webauthn = await Webauthn.deploy();
    await webauthn.deployed();

    const publicKey = Buffer.from("fdf8bce27f54e06f3aee3b6a542db1ab1f2418d7370a78b150d06965f942b14a470cdee69ab50e610c39b840681bf816b030f4a0a5d5af02ce27dcce6bede89f", "hex");
    const signature = Buffer.from("30440220655c9a457615aac594d92fb6d842f0e910e5ee6677cddbcddaea624f3203f0e702207b71a302b06c91a52b9c4ba5a7fb85226738b02c144e8ee177d034022a79c946", "hex");
    const authenticatorData = Buffer.from("f8e4b678e1c62f7355266eaa4dc1148573440937063a46d848da1e25babbd20b010000004d", "hex");
    const clientData = Buffer.from("7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224e546f2d3161424547526e78786a6d6b61544865687972444e5833697a6c7169316f776d4f643955474a30222c226f726967696e223a2268747470733a2f2f66726573682e6c65646765722e636f6d222c2263726f73734f726967696e223a66616c73657d", "hex");
    const clientChallenge = Buffer.from("353a3ed5a0441919f1c639a46931de872ac3357de2ce5aa2d68c2639df54189d", "hex");

    // Get on the "challenge" key value following "
    const challengeOffset = clientData.indexOf("226368616c6c656e6765223a", 0, "hex") + 12 + 1;    
    const signatureParsed = derToRS(signature);

	/*
    const result = await webauthn.checkSignature(authenticatorData, 0x01, clientData, clientChallenge, challengeOffset,
        [ ethers.BigNumber.from("0x" + signatureParsed[0].toString('hex')), ethers.BigNumber.from("0x" + signatureParsed[1].toString('hex'))],
        [ ethers.BigNumber.from("0x" + publicKey.slice(0, 32).toString('hex')), ethers.BigNumber.from("0x" + publicKey.slice(32).toString('hex'))]
    );
    expect(result);
*/
    
    const result = await webauthn.validate(authenticatorData, 0x01, clientData, clientChallenge, challengeOffset,
        [ ethers.BigNumber.from("0x" + signatureParsed[0].toString('hex')), ethers.BigNumber.from("0x" + signatureParsed[1].toString('hex'))],
        [ ethers.BigNumber.from("0x" + publicKey.slice(0, 32).toString('hex')), ethers.BigNumber.from("0x" + publicKey.slice(32).toString('hex'))]
    );
    await result.wait();
    

  })
});
