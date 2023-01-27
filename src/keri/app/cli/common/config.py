# -*- encoding: utf-8 -*-
"""
keri.kli.common.config

"""
import json
from dataclasses import dataclass, asdict
from json import JSONDecodeError
from typing import Optional, List

from keri import kering


@dataclass
class Config:
    """
    Config representation of prefix configuration
    """
    name: str  # Alias for prefix
    witnessExpire: Optional[int] = 60  # timeout for witness connection
    witnesses: Optional[List[str]] = None  # list of witness nodes
    transferable: Optional[bool] = None  # Use transferable derivation code

    def __iter__(self):
        return iter(asdict(self))


def loadConfig(file: str) -> Config:
    """
        Parameters:
            file (str): file location to load from
    """
    cfg = None
    if file != '':
        with open(file, "r") as f:
            cfg = Config(**json.loads(f.read()))
    return cfg


def parseData(data_path):
    """
    Load JSON data from data path

    Parameters:
        data_path (str): path to file containing anchor/seal configuration data
    """
    try:
        if data_path.startswith("@"):
            f = open(data_path[1:], "r")
            data = json.load(f)
        else:
            data = json.loads(data_path)
    except json.JSONDecodeError:
        raise kering.ConfigurationError("data supplied to anchor in a seal must be valid JSON")

    if not isinstance(data, list):
        data = [data]

    return data


def checkRequiredArgs(args, required_args):
    """
    Ensure required arguments are present or raise error.

    Parameters:
        args (Namespace)    : the command line arguments passed in
        required_args (list): a list of strings of the names of required arguments
    """
    for required_arg in required_args:
        try:
            result = getattr(args, required_arg)
            if result is None:
                raise ValueError(f"Required arg {required_arg} not present when config file not specified")
        except AttributeError as e:
            print("all of", required_args, "must be present if not using a configuration file")
            raise ValueError(f"Required arg {required_arg} not present when config file not specified") from e


def loadFileOptions(file_path, options_class):
    """
    Load configuration JSON from the file_path and instantiate an options_class from it

    Parameters:
        file_path (str)      : the path to the configuration file to load
        options_class (class): the type of class to instantiate from the parsed JSON of the file loaded
    """
    try:
        f = open(file_path)
        config = json.load(f)

        options = options_class(**config)
    except FileNotFoundError as e:
        print("config file", file_path, "not found")
        raise e
    except JSONDecodeError as e:
        print("config file", file_path, "not valid JSON")
        raise e

    return options
