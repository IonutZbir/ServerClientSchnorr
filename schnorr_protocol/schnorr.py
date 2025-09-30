import hashlib
import random

from .groups import GroupType, Rfc3526
# from groups import GroupType, Rfc3526

class Schnorr:
    def __init__(self, group_id: GroupType, filename: str = None):
        self._crypto_group = (
            Rfc3526(group_id, filename) if filename is not None else Rfc3526(group_id)
        )
        self._p = self._crypto_group.p
        self._g = self._crypto_group.g
        self._q = self._crypto_group.q
        
        # print("P", self._p)
        # print("G", self._g)
        # print("Q", self._q)
        
        self._public_key = None
        self._public_key_temp = None

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
    def public_key(self) -> int:
        return self._public_key

    @public_key.setter
    def public_key(self, value: int):
        self._public_key = value

    @property
    def public_key_temp(self) -> int:
        return self._public_key_temp

    @public_key_temp.setter
    def public_key_temp(self, value: int):
        self._public_key_temp = value

    def compute_challenge(self, message: str) -> int:
        data = str(self.public_key_temp) + str(self.public_key) + message
        return int(hashlib.sha256(data.encode()).hexdigest(), 16) % self.q

class SchnorrProver(Schnorr):
    def __init__(self, group_id: GroupType, filename: str = None):
        super().__init__(group_id, filename)

        self._alpha = None

        self._alpha_temp = None

    @property
    def alpha(self) -> int:
        return self._alpha

    @alpha.setter
    def alpha(self, value: int):
        self._alpha = value

    @property
    def public_key(self) -> int:
        if self._public_key is None:
            self._public_key = pow(self._g, self._alpha, self._p)
        return self._public_key

    @property
    def public_key_temp(self) -> int:
        self._alpha_temp = random.randint(1, self.q - 1)
        self._public_key_temp = pow(self.g, self._alpha_temp, self.p)
        return self._public_key_temp

    def gen_keys(self):
        self._alpha = random.randint(1, self._q - 1)
        self._public_key = pow(self._g, self._alpha, self._p)  # commitment

    def response(self, challenge: int) -> int:  # response
        return (self._alpha_temp + self.alpha * challenge) % self.q

    def sign_message(self, message: str) -> dict[str, int]:
        challenge = self.compute_challenge(message)
        sign = {"public_key_temp": self._public_key_temp, "response": self.response(challenge)}
        return sign
    
    def sign_message_encoded(self, message: str) -> dict[str, int]:
        sign = self.sign_message(message)
        
        return {"public_key_temp": hex(sign["public_key_temp"]), "response": hex(sign["response"])}
        

class SchnorrVerifier(Schnorr):
    def __init__(self, group_id: GroupType, filename: str = None):
        super().__init__(group_id, filename)

        self._challenge = random.randint(0, self._q - 1)

    @property
    def challenge(self) -> int:  # challenge
        return self._challenge

    def check(self, response: int) -> bool:  # check
        left = pow(self.g, response, self.p)
        right = (self.public_key_temp * pow(self.public_key, self.challenge, self.p)) % self.p
        return left == right
    
    def verify_sign(self, sign: dict, message: str) -> bool:
        self.public_key_temp = sign["public_key_temp"]
        self._challenge = self.compute_challenge(message)
        return self.check(sign["response"])

# Example of usage
def schnorr_id():
    prover = SchnorrProver(GroupType.MODP_2048)
    verifier = SchnorrVerifier(GroupType.MODP_2048)

    prover.gen_keys()

    verifier.public_key = prover.public_key
    verifier.public_key_temp = prover.public_key_temp

    result = verifier.check(prover.response(verifier.challenge))

    print(result)

def schnorr_sign():
    # slave sends pk_slave to server (V)
    # server (V) sends message to client (P)
    # client (P) signs message and sends it to server (V)
    # server (V) verify the sign
    
    prover = SchnorrProver(GroupType.MODP_2048)
    verifier = SchnorrVerifier(GroupType.MODP_2048)
    
    prover.gen_keys()
    
    pk_slave = "129783127381201648912" 
    
    message = hashlib.sha256(pk_slave.encode()).hexdigest()
    
    verifier.public_key = prover.public_key
    
    sign = prover.sign_message(message)
    
    result = verifier.verify_sign(sign, message)
    
    print(result)
    
if __name__ == "__main__":
    schnorr_sign()
    schnorr_id()
   
