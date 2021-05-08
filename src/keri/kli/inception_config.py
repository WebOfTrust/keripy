from dataclasses import dataclass


@dataclass
class Config:
    name: str  # Alias for KEL
    with_tel: bool  # Needs companion REL/TEL
    transferable: bool  # Use transferable derivation code
