from hashlib import pbkdf2_hmac, sha256
from random import choice, random
from random import seed as _seed
from string import digits


class GenPassword:
    def __init__(self, seed: list, username: str, website: str, length: int = 32):
        seeds = "".join(sha256(str(key).encode()).hexdigest() for key in seed)

        # make sure length is greater than 8
        if length < 8:
            raise ValueError("Password length must be greater than 8 characters")

        # set the seed
        # combine the public keys of username and website with the private key
        # of the password and use the hash of the result as the seed
        self.seed = pbkdf2_hmac(
            hash_name="sha256",
            password=str(
                sha256((username + website + seeds).encode()).hexdigest()
            ).encode(),
            salt=str(sha256((seeds + username).encode()).hexdigest()).encode(),
            iterations=length,
        )

        _seed(self.seed)

        # generics
        self.username = username
        self.length = length
        self.website = website
        self.private_key = seed
        self.length = length

        # sounds
        self.sounds = "bdfghjklmnprstvwyz"
        self.vowels = "aeiou"

        # words
        words = self._gen_words()
        self.words: list = []
        self._true_words = words

        # actual password
        self.value = self.generate()

    def _gen_words(self) -> list:
        """Generate the list of words to be used in the password

        Returns:
            list: A list of words to be used in the password
        """
        return [self._gen_word() for _ in range(self.length - 1 - self.length // 3)]

    def _gen_word(self) -> str:
        """Generate a single word of the password

        Returns:
            str: A single word of the password
        """
        word = ""
        word += choice(self.sounds)
        word += choice(self.vowels)
        word += choice(self.sounds)
        return word

    def generate(self) -> str:
        """Generate a password"""
        result = ""
        while len(result) < self.length and len(self._true_words) > 0:
            rand = random()
            if rand < 0.33:
                word = choice(self._true_words)
                self._true_words.remove(word)
                self.words.append(word)
                result += word
            else:
                result += choice(digits)

        if self.words[-1] not in result:
            # determine if the length is correct
            if len(result) - self.length > 3:
                result += choice(self.words)
            else:
                # remove a random digit from the result until the length is 3
                # less than the length of the password
                while len(result) - self.length < 3:
                    result = result.replace(choice(digits), "", 1)

        while len(result) < self.length:
            result += choice(digits)
        while len(result) > self.length:
            result = result.replace(choice(digits), "", 1)

        return result

    def readable(self):
        """Make the password readable by seperting the words with a space.
        Return the password as a string."""
        new = self.value
        for word in self.words:
            new = new.replace(word, f"{word} ")
        return new

    def __str__(self) -> str:
        return self.value

    def __add__(self, other):
        return str(self.value) + str(other)

    def __len__(self):
        return len(self.value)

    def __repr__(self) -> str:
        return self.value
