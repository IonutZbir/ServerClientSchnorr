from enum import Enum
import json
import os


class GroupType(Enum):
    MODP_1536 = "modp-1536"
    MODP_2048 = "modp-2048"
    MODP_3072 = "modp-3072"
    MODP_4096 = "modp-4096"

    @classmethod
    def get_all_groups_str(cls):
        return [cls.MODP_1536.group_id, cls.MODP_2048.group_id, cls.MODP_3072.group_id, cls.MODP_4096.group_id]
    
    @classmethod
    def get_all_groups_obj(cls):
        return [cls.MODP_1536, cls.MODP_2048, cls.MODP_3072, cls.MODP_4096]
    
    def __init__(self, group_id):
        self.group_id = group_id

    def __str__(self):
        return self.group_id


class Rfc3526:
    def __init__(self, group_id: GroupType, filename: str = None):
        self._group_id = group_id
        self._filename = filename
        if filename is None:
            base_path = os.path.dirname(__file__)
            self._filename = os.path.join(base_path, "rfc3526_groups.json")
        self._groups = self._load_groups()
        
        self._p = self._groups[self._group_id]["p"]
        self._g = self._groups[self._group_id]["g"]
        self._q = (self._p - 1) // 2

    def _load_groups(self) -> dict:
        try:
            with open(self._filename, "r") as f:
                raw = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            raise RuntimeError(f"Errore nel caricamento del file '{self._filename}': {e}")

        groups = {}
        for key, params in raw.items():
            try:
                group_enum = GroupType(key) 
                if not isinstance(params, dict) or "p" not in params or "g" not in params:
                    raise ValueError(f"Al gruppo '{key}' mancano i seguenti parametri: 'p'/'g'")
                groups[group_enum] = {"p": int(params["p"], 16), "g": params["g"]}
            except ValueError:
                raise RuntimeError(f"Il gruppo '{key}' non è valido per GroupType")
            except Exception as e:
                raise RuntimeError(f"Errore nel processare il gruppo '{key}': {e}")
        return groups

    @property
    def p(self):
        return self._p

    @property
    def g(self):
        return self._g

    @property
    def q(self):
        return self._q
    
    @property
    def group_id(self):
        return self._group_id
