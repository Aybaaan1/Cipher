def caesar_cipher(text, key, encrypt)
  shift = encrypt ? key : -key
  text.chars.map do |char|
    if char.match(/[A-Za-z]/)
      base = char.ord < 91 ? 'A'.ord : 'a'.ord
      ((char.ord - base + shift) % 26 + base).chr
    else
      char
    end
  end.join
end

def vigenere_cipher(text, key, encrypt)
  key = key.upcase
  key_chars = key.chars.map { |c| c.ord - 'A'.ord }
  result = []
  key_index = 0

  text.chars.each do |char|
    if char.match(/[A-Za-z]/)
      base = char.ord < 91 ? 'A'.ord : 'a'.ord
      shift = encrypt ? key_chars[key_index % key.length] : -key_chars[key_index % key.length]
      result << ((char.ord - base + shift) % 26 + base).chr
      key_index += 1
    else
      result << char
    end
  end

  result.join
end
