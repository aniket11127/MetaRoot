const hre = require("hardhat");

async function main() {
  const Contract = await hre.ethers.getContractFactory("ChainFoldProtocol");
  const instance = await Contract.deploy();
  await instance.deployed();

  console.log("ChainFoldProtocol deployed to:", instance.address);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
