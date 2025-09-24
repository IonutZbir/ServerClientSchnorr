from mnemonic import Mnemonic

class TrieNode:
    def __init__(self, char=None):
        self.children = [None]*26
        self.isEndOfWord = False
        self.char = char

    def _char(self, index: int) -> str:
        return chr(ord('a') + index)

    def __str__(self):
        children_chars = [child.char for child in self.children if child]
        return f"<TrieNode>Char: {self.char} - Children: {children_chars} - IsEndOfWord: {self.isEndOfWord}"

class Trie:
    def __init__(self):
        self.root = TrieNode()
    
    def createTreeFromWords(self, words: list[str]) -> bool:
        if not words:
            return False
        
        for word in words:
            if not self.insert(word):
                return False
        
        return True
    
    def insert(self, word: str) -> bool:
        if not word:
            return False
        
        curr = self.root
        
        for c in word:
            index = self._index(c)
            if index < 0 or index >= 26:
                continue  # ignora caratteri non alfabetici
            if curr.children[index] is None:
                curr.children[index] = TrieNode(c)
            
            curr = curr.children[index]
        
        curr.isEndOfWord = True
        return True
    
    def search(self, prefix: str) -> TrieNode | None:
        curr = self.root
        for c in prefix:
            index = self._index(c)
            if index < 0 or index >= 26 or curr.children[index] is None:
                return None
            curr = curr.children[index]
        return curr
    
    def stringsStartsWith(self, prefix: str) -> list[str] | None:
        node = self.search(prefix)
        if not node:
            return None
        results = []
        self._collect(node, prefix, results)
        return results if results else None

    def _collect(self, node: TrieNode, prefix: str, results: list[str]):
        if node.isEndOfWord:
            results.append(prefix)
        for i, child in enumerate(node.children):
            if child:
                self._collect(child, prefix + self._char(i), results)
            
    def _index(self, char: str) -> int:
        return ord(char) - ord('a') 
    
    def _char(self, index: int) -> str:
        return chr(ord('a') + index)
    
    def __str__(self):
        return "<Trie>"

if __name__ == "__main__":
    mnemo = Mnemonic("italian")
    wordlist = mnemo.wordlist
    trie = Trie()
    trie.createTreeFromWords(wordlist)
    
    prefix = "ab"
    print(f"Prefisso: {prefix} - {trie.search(prefix)}")
    
    words_ab = trie.stringsStartsWith(prefix)
    print(words_ab)
