// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Burnable} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";

/// META: fixed-supply ERC-20 token. Supply is minted once at deployment.
contract MetaCoin is ERC20, ERC20Burnable {
    constructor(address treasury, uint256 wholeCoins) ERC20("MetaCoin", "META") {
        _mint(treasury, wholeCoins * 10 ** decimals());
    }
    function decimals() public pure override returns (uint8) { return 8; }
}
