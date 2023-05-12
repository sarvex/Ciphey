"""
This is Hashbuster but slightly modified to work with Ciphey.
Why reinvent the wheel?
Changes (that I can remember)
* timeout set, as hashbuster took AGES before timeout was set.
https://github.com/s0md3v/Hash-Buster
"""

import re
from typing import Dict, List, Optional

import requests
import logging
from rich.logging import RichHandler

from ciphey.iface import Config, Cracker, CrackInfo, CrackResult, ParamSpec, T, registry

thread_count = 4


def alpha(ctext, hashtype):
    return None


def beta(ctext, hashtype):
    try:
        response = requests.get(
            "https://hashtoolkit.com/reverse-hash/?hash=", ctext, timeout=5
        ).text
    except requests.exceptions.ReadTimeout as e:
        logging.info(f"Beta failed timeout {e}")
    if match := re.search(r'/generate-hash/?text=.*?"', response):
        return match[1]
    return None


def gamma(ctext, hashtype):
    try:
        response = requests.get(
            f"https://www.nitrxgen.net/md5db/{ctext}", timeout=5
        ).text
    except requests.exceptions.ReadTimeout as e:
        logging.info(f"Gamma failed with {e}")
    return response if response else None


def delta(ctext, hashtype):
    return None


def theta(ctext, hashtype):
    try:
        response = requests.get(
            f"https://md5decrypt.net/Api/api.php?hash={ctext}&hash_type={hashtype}&email=deanna_abshire@proxymail.eu&code=1152464b80a61728",
            timeout=5,
        ).text
    except requests.exceptions.ReadTimeout as e:
        logging.info(f"Gamma failed with {e}")
    return response if response != "" else None


md5 = [gamma, alpha, beta, theta, delta]
sha1 = [alpha, beta, theta, delta]
sha256 = [alpha, beta, theta]
sha384 = [alpha, beta, theta]
sha512 = [alpha, beta, theta]


result = {}


def crack(ctext):
    raise "Error Crack is called"


def threaded(ctext):
    if resp := crack(ctext):
        print(f"{ctext} : {resp}")
        result[ctext] = resp


@registry.register
class HashBuster(Cracker[str]):
    @staticmethod
    def getTarget() -> str:
        return "hash"

    @staticmethod
    def getParams() -> Optional[Dict[str, ParamSpec]]:
        return None

    @staticmethod
    def priority() -> float:
        return 0.05

    def getInfo(self, ctext: T) -> CrackInfo:
        # TODO calculate these properly
        return CrackInfo(
            success_likelihood=0.5,
            success_runtime=5,
            failure_runtime=5,
        )

    def attemptCrack(self, ctext: T) -> List[CrackResult]:
        logging.info("Starting to crack hashes")
        result = False

        candidates = []
        if len(ctext) == 32:
            for api in md5:
                r = api(ctext, "md5")
                if result is not None or r is not None:
                    logging.debug("MD5 returns True {r}")
                    candidates.append(result, "MD5")
        elif len(ctext) == 40:
            for api in sha1:
                r = api(ctext, "sha1")
                if result is not None and r is not None:
                    logging.debug("sha1 returns true")
                    candidates.append(result, "SHA1")
        elif len(ctext) == 64:
            for api in sha256:
                r = api(ctext, "sha256")
                if result is not None and r is not None:
                    logging.debug("sha256 returns true")
                    candidates.append(result, "SHA256")
        elif len(ctext) == 96:
            for api in sha384:
                r = api(ctext, "sha384")
                if result is not None and r is not None:
                    logging.debug("sha384 returns true")
                    candidates.append(result, "SHA384")
        elif len(ctext) == 128:
            for api in sha512:
                r = api(ctext, "sha512")
                if result is not None and r is not None:
                    logging.debug("sha512 returns true")
                    candidates.append(result, "SHA512")

        # TODO what the fuck is this code?
        logging.debug(f"Hash buster returning {result}")
        # TODO add to 5.1 make this return multiple possible candidates
        return [CrackResult(value=candidates[0][0], misc_info=candidates[1][1])]

    def __init__(self, config: Config):
        super().__init__(config)
