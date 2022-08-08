from random import seed as _seed, choice, random
from string import digits
class Password(object):
    def __init__(self, length=32, seed=None):
        if length < 8:
            raise ValueError("Password length must be at least 8 characters")
        if seed:
            _seed(seed)
        else:
            _seed()
        self.length = length
        self.sounds = "bdfghjklmnprstvwyz"
        self.vowels = "aeiou"
        words = self._gen_words()
        self._true_words = words
        self.words = []
        self.value = self.generate()


    def _gen_words(self):
        words = []
        for _ in range(self.length - 1 - (2 * self.length // 3)):
            words.append(self._gen_word())
        return words

    def _gen_word(self):
        word = ""
        word += choice(self.sounds)
        word += choice(self.vowels)
        word += choice(self.sounds)
        return word

    def generate(self):
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
                # remove a random digit from the result until the length is 3 less than the length of the password
                while len(result) - self.length < 3:
                    result = result.replace(choice(digits), "", 1)

        while len(result) < self.length:
            result += choice(digits)
        while len(result) > self.length:
            result = result.replace(choice(digits), "", 1)

        return result

    def readable(self):
        # Make the password readable by seperting the words with a space. Return the password as a string.
        new = self.value
        for word in self.words:
            new = new.replace(word, word + " ")
        return new

    def __str__(self) -> str:
        return self.value

    def __add__(self, other):
        return str(self.value) + str(other)

    def __len__(self):
        return len(self.value)
