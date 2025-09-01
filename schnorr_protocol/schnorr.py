import random

from .groups import GroupType, Rfc3526


class SchnorrProver:
    def __init__(self, group_id: GroupType, filename: str = None):
        self._crypto_group = (
            Rfc3526(group_id, filename) if filename is not None else Rfc3526(group_id)
        )
        self._p = self._crypto_group.p
        self._g = self._crypto_group.g
        self._q = self._crypto_group.q

        self._alpha = None
        self._public_key = None

        self._alpha_temp = None
        self._public_key_temp = None

    @property
    def alpha(self) -> int:
        return self._alpha

    @alpha.setter
    def alpha(self, value: int):
        self._alpha = value
    
    @property
    def public_key(self) -> int:
        return self._public_key

    @property
    def p(self) -> int:
        return self._p

    @property
    def g(self) -> int:
        return self._g

    @property
    def q(self) -> int:
        return self._q
    
    @property
    def crypto_group(self) -> GroupType:
        return self._crypto_group.group_id

    def gen_keys(self):
        self._alpha = random.randint(1, self._q - 1)
        self._public_key = pow(self._g, self._alpha, self._p)  # commitment

    @property
    def public_key_temp(self) -> int:
        self._alpha_temp = random.randint(1, self.q - 1)
        self._public_key_temp = pow(self.g, self._alpha_temp, self.p)
        return self._public_key_temp

    def response(self, challenge: int) -> int:  # response
        return (self._alpha_temp + self.alpha * challenge) % self.q


class SchnorrVerifier:
    def __init__(self, group_id: GroupType, filename: str = None):
        self._crypto_group = (
            Rfc3526(group_id, filename) if filename is not None else Rfc3526(group_id)
        )
        self._p = self._crypto_group.p
        self._g = self._crypto_group.g
        self._q = self._crypto_group.q

        self._public_key = None
        self._public_key_temp = None

        self._challenge = random.randint(0, self._q - 1)

    @property
    def p(self) -> int:
        return self._p

    @property
    def g(self) -> int:
        return self._g

    @property
    def q(self) -> int:
        return self._q
    
    @property
    def crypto_group(self) -> GroupType:
        return self._crypto_group.group_id

    @property
    def challenge(self) -> int:  # challenge
        return self._challenge

    @property
    def public_key(self) -> int:
        return self._public_key

    @property
    def public_key_temp(self) -> int:
        return self._public_key_temp

    @public_key.setter
    def public_key(self, public_key: int):
        self._public_key = public_key

    @public_key_temp.setter
    def public_key_temp(self, public_key_temp: int):
        self._public_key_temp = public_key_temp

    def check(self, response: int) -> bool:  # check
        left = pow(self.g, response, self.p)
        right = (self.public_key_temp * pow(self.public_key, self.challenge, self.p)) % self.p
        return left == right


# Example of usage
if __name__ == "__main__":

    prover = SchnorrProver(GroupType.MODP_2048)
    verifier = SchnorrVerifier(GroupType.MODP_2048)
    
    prover.gen_keys()
    
    verifier.public_key = prover.public_key
    verifier.public_key_temp = prover.public_key_temp

    result = verifier.check(prover.response(verifier.challenge))
    print(result)


    print(prover.crypto_group)