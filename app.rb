require 'sinatra'
require 'json'
require './ciphers'
require 'openssl'
require 'base64'

get '/' do
  erb :index
end

get '/caesar' do
  erb :caesar
end

get '/vigenere' do
  erb :vigenere
end

get '/playfair' do
  erb :playfair
end

get '/scolumnar' do
  erb :scolumnar
end

get '/dcolumnar' do
  erb :dcolumnar
end

get '/aes' do
  erb :aes
end

post '/result' do
  cipher_type = params[:cipher_type]  # To differentiate between Caesar, Vigenère, and Playfair
  text = params[:text]
  key = params[:key]
  action = params[:action]

  if cipher_type == 'Caesar'
    key = key.to_i
    @result = if action == 'Encrypt'
                caesar_encrypt(text, key)
              elsif action == 'Decrypt'
                caesar_decrypt(text, key)
              else
                "Invalid action"
              end
    @back_link = '/caesar'
  elsif cipher_type == 'Vigenere'
    @result = if action == 'Encrypt'
                vigenere_encrypt(text, key)
              elsif action == 'Decrypt'
                vigenere_decrypt(text, key)
              else
                "Invalid action"
              end
    @back_link = '/vigenere'
  else
    @result = "Invalid cipher type"
    @back_link = '/'
  end

  erb :result
end

###################################################



post '/pfresult' do
  cipher_type = params[:cipher_type]  # To differentiate between Caesar, Vigenère, and Playfair
  text = params[:text]
  key = params[:key]
  action = params[:action]

  if cipher_type == 'Playfair'
    if action == 'Encrypt'
      @result, @table_steps = playfair_encrypt(text, key)
    elsif action == 'Decrypt'
      @result, @table_steps = playfair_decrypt(text, key)
    else
      @result = "Invalid action"
      @table_steps = []
    end
    @back_link = '/playfair'
  else
    @result = "Invalid cipher type"
    @table_steps = []
    @back_link = '/'
  end

  erb :pfresult
end



###################################################



post '/scresult' do
  cipher_type = params[:cipher_type]  # To differentiate between Single Columnar
  text = params[:text]
  key = params[:key]
  action = params[:action]

  if cipher_type == 'Single Columnar'
    @result, @table_steps = if action == 'Encrypt'
                              single_columnar_encrypt(text, key)
                            elsif action == 'Decrypt'
                              single_columnar_decrypt(text, key)
                            else
                              "Invalid action"
                            end
    @key = key
    @back_link = '/scolumnar'
  else
    @result = "Invalid cipher type"
    @back_link = '/'
  end

  erb :scresult
end

def column_order(key)
  # Generate column order based on alphabetical sorting of the key
  key.chars.each_with_index.sort_by { |char, _| char }.map { |_, index| index }
end

def create_table(text, columns)
  # Create a table row-by-row based on the text and column count
  rows = (text.length.to_f / columns).ceil
  table = Array.new(rows) { Array.new(columns, ' ') } # Initialize with spaces to preserve them

  # Fill the table row by row
  text.chars.each_with_index do |char, index|
    row = index / columns
    col = index % columns
    table[row][col] = char
  end
  table
end

def read_table_by_columns(table, column_order)
  # Read the table column by column in the given column order, preserving spaces
  column_order.flat_map do |col_index|
    table.map { |row| row[col_index] }
  end.join
end

def reverse_read_table_by_columns(text, rows, column_order)
  # Reverse the columnar reading process to reconstruct the table
  columns = column_order.size
  table = Array.new(rows) { Array.new(columns, ' ') }
  current_pos = 0

  column_order.each do |col_index|
    rows.times do |row_index|
      if current_pos < text.length
        table[row_index][col_index] = text[current_pos]
        current_pos += 1
      end
    end
  end
  table
end

# Single Columnar Encryption Function
def single_columnar_encrypt(plain_text, key)
  # Step 1: Create a table using the length of the key
  table = create_table(plain_text, key.length)
  column_order1 = column_order(key)

  # Step 2: Read the table column by column according to the key's order
  encrypted_text = read_table_by_columns(table, column_order1)

  # Return encrypted text and the table for visualization
  [encrypted_text, table]
end

# Single Columnar Decryption Function
def single_columnar_decrypt(cipher_text, key)
  # Step 1: Create the table structure based on the length of the cipher text and key length
  columns = key.length
  rows = (cipher_text.length.to_f / columns).ceil
  column_order1 = column_order(key)

  # Step 2: Reverse the columnar reading to fill the table
  table = reverse_read_table_by_columns(cipher_text, rows, column_order1)

  # Step 3: Read the table row by row to create the decrypted text
  decrypted_text = table.map { |row| row.compact.join }.join

  # Return decrypted text and the table for visualization
  [decrypted_text, table]
end


###################################################
post '/dcresult' do
  puts "DEBUG: params = #{params.inspect}"  # Inspect params for debugging

    cipher_type = params[:cipher_type]
    text = params[:text]
    key1 = params[:key1]
    key2 = params[:key2]
    action = params[:action]

    if cipher_type == 'Double Columnar'
      case action
      when 'Encrypt'
        @result, @table_steps1, @table_steps2 = double_columnar_encrypt(text, key1, key2)
      when 'Decrypt'
        @result, @table_steps1, @table_steps2 = double_columnar_decrypt(text, key1, key2)
      else
        # Handle any unexpected action here
        @error = "Invalid action"
      end
      @key1 = key1
      @key2 = key2
      @back_link = '/dcolumnar'
    else
      @result = "Invalid cipher type"
      @back_link = '/'
    end

    erb :dcresult
  end

  def column_order(key)
    # Generate column order based on alphabetical sorting of the key
    key.chars.each_with_index.sort_by { |char, _| char }.map { |_, index| index }
  end
  
  def create_table(text, columns)
    # Create a table row-by-row based on the text and column count
    rows = (text.length.to_f / columns).ceil
    table = Array.new(rows) { Array.new(columns, ' ') } # Initialize with spaces to preserve them
    
    # Fill the table row by row
    text.chars.each_with_index do |char, index|
      row = index / columns
      col = index % columns
      table[row][col] = char
    end
    table
  end
  
  def read_table_by_columns(table, column_order)
    # Read the table column by column in the given column order, preserving spaces
    column_order.flat_map do |col_index|
      table.map { |row| row[col_index] }
    end.join
  end
  
  def reverse_read_table_by_columns(text, rows, column_order)
    # Reverse the columnar reading process to reconstruct the table
    columns = column_order.size
    table = Array.new(rows) { Array.new(columns, ' ') }
    current_pos = 0
  
    column_order.each do |col_index|
      rows.times do |row_index|
        if current_pos < text.length
          table[row_index][col_index] = text[current_pos]
          current_pos += 1
        end
      end
    end
    table
  end
  
  def double_columnar_encrypt(text, key1, key2)
    # Step 1: Create Table 1 with Key 1 and read by columns
    table1 = create_table(text, key1.length)
    column_order1 = column_order(key1)
    intermediate_text = read_table_by_columns(table1, column_order1)
  
    # Step 2: Create Table 2 with Key 2 and read by columns
    table2 = create_table(intermediate_text, key2.length)
    column_order2 = column_order(key2)
    cipher_text = read_table_by_columns(table2, column_order2)
  
    # Return encrypted text and both tables for reference
    [cipher_text, table1, table2]
  end
  
  def double_columnar_decrypt(cipher_text, key1, key2)
    # Step 1: Reverse Table 2 based on Key 2
    column_order2 = column_order(key2)
    rows2 = (cipher_text.length.to_f / key2.length).ceil
    table2 = reverse_read_table_by_columns(cipher_text, rows2, column_order2)
    intermediate_text = table2.flat_map(&:join).join
  
    # Step 2: Reverse Table 1 based on Key 1
    column_order1 = column_order(key1)
    rows1 = (intermediate_text.length.to_f / key1.length).ceil
    table1 = reverse_read_table_by_columns(intermediate_text, rows1, column_order1)
    plain_text = table1.flat_map(&:join).join
  
    # Return decrypted text and both tables for reference
    [plain_text, table1, table2]
  end
##################################

# Caesar cipher methods
def caesar_encrypt(text, key)
  text.chars.map { |c| (c.ord + key).chr }.join
end

def caesar_decrypt(text, key)
  text.chars.map { |c| (c.ord - key).chr }.join
end

# Vigenère cipher methods
def vigenere_encrypt(text, key)
  key = key.upcase
  encrypted_text = ""

  text.chars.each_with_index do |char, index|
    if char.match?(/[A-Za-z]/)  # Encrypt only alphabetic characters
      shift = key[index % key.length].ord - 'A'.ord
      base = char.match?(/[A-Z]/) ? 'A'.ord : 'a'.ord
      encrypted_char = ((char.ord - base + shift) % 26 + 26) % 26 + base
      encrypted_text += encrypted_char.chr
    else
      encrypted_text += char  # Keep non-alphabetic characters as is
    end
  end

  encrypted_text
end

def vigenere_decrypt(text, key)
  key = key.upcase
  decrypted_text = ""

  text.chars.each_with_index do |char, index|
    if char.match?(/[A-Za-z]/)  # Decrypt only alphabetic characters
      shift = key[index % key.length].ord - 'A'.ord
      base = char.match?(/[A-Z]/) ? 'A'.ord : 'a'.ord
      decrypted_char = ((char.ord - base - shift) % 26 + 26) % 26 + base
      decrypted_text += decrypted_char.chr
    else
      decrypted_text += char  # Keep non-alphabetic characters as is
    end
  end

  decrypted_text
end

# Playfair cipher methods
def playfair_encrypt(text, key)
  key = prepare_key(key)
  text_pairs = prepare_text_pairs(text, true)
  encrypted_text = ""
  table_steps = [] # To store intermediate steps

  text_pairs.each do |pair|
    a, b = pair.chars
    if key.include?(a) && key.include?(b)
      a_pos = key.index(a)
      b_pos = key.index(b)
      if a_pos / 5 == b_pos / 5  # Same row
        encrypted_a = key[(a_pos + 1) % 5 + (a_pos / 5) * 5]
        encrypted_b = key[(b_pos + 1) % 5 + (b_pos / 5) * 5]
        encrypted_text += encrypted_a + encrypted_b
        table_steps << { pair: "#{a}#{b}", result: "#{encrypted_a}#{encrypted_b}", rule: "Same row" }
      elsif a_pos % 5 == b_pos % 5  # Same column
        encrypted_a = key[(a_pos + 5) % 25]
        encrypted_b = key[(b_pos + 5) % 25]
        encrypted_text += encrypted_a + encrypted_b
        table_steps << { pair: "#{a}#{b}", result: "#{encrypted_a}#{encrypted_b}", rule: "Same column" }
      else  # Rectangle rule
        encrypted_a = key[(a_pos / 5) * 5 + (b_pos % 5)]
        encrypted_b = key[(b_pos / 5) * 5 + (a_pos % 5)]
        encrypted_text += encrypted_a + encrypted_b
        table_steps << { pair: "#{a}#{b}", result: "#{encrypted_a}#{encrypted_b}", rule: "Rectangle" }
      end
    else
      encrypted_text += a + b
      table_steps << { pair: "#{a}#{b}", result: "#{a}#{b}", rule: "No encryption" }
    end
  end

  [encrypted_text, table_steps]
end

def playfair_decrypt(text, key)
  key = prepare_key(key)
  text_pairs = prepare_text_pairs(text, false)
  decrypted_text = ""
  table_steps = [] # To store intermediate steps

  text_pairs.each do |pair|
    a, b = pair.chars
    if key.include?(a) && key.include?(b)
      a_pos = key.index(a)
      b_pos = key.index(b)
      if a_pos / 5 == b_pos / 5  # Same row
        decrypted_a = key[(a_pos - 1) % 5 + (a_pos / 5) * 5]
        decrypted_b = key[(b_pos - 1) % 5 + (b_pos / 5) * 5]
        decrypted_text += decrypted_a + decrypted_b
        table_steps << { pair: "#{a}#{b}", result: "#{decrypted_a}#{decrypted_b}", rule: "Same row" }
      elsif a_pos % 5 == b_pos % 5  # Same column
        decrypted_a = key[(a_pos - 5 + 25) % 25]
        decrypted_b = key[(b_pos - 5 + 25) % 25]
        decrypted_text += decrypted_a + decrypted_b
        table_steps << { pair: "#{a}#{b}", result: "#{decrypted_a}#{decrypted_b}", rule: "Same column" }
      else  # Rectangle rule
        decrypted_a = key[(a_pos / 5) * 5 + (b_pos % 5)]
        decrypted_b = key[(b_pos / 5) * 5 + (a_pos % 5)]
        decrypted_text += decrypted_a + decrypted_b
        table_steps << { pair: "#{a}#{b}", result: "#{decrypted_a}#{decrypted_b}", rule: "Rectangle" }
      end
    else
      decrypted_text += a + b
      table_steps << { pair: "#{a}#{b}", result: "#{a}#{b}", rule: "No decryption" }
    end
  end

  [decrypted_text, table_steps]
end

def prepare_key(key)
  key = key.upcase.gsub(/[^A-Z]/, '').chars.uniq
  alphabet = ('A'..'Z').to_a - ['J']  # 'J' is usually combined with 'I'
  key += alphabet - key
  key.join
end

def prepare_text_pairs(text, encrypt = true)
  text = text.upcase.gsub(/[^A-Z]/, '').gsub('J', 'I')
  text_pairs = []
  i = 0

  # Add a 'Z' if the length of the text is odd
  text += 'Z' if text.length.odd?

  while i < text.length
    if i + 1 < text.length && text[i] == text[i + 1]
      text_pairs << text[i] + 'X'
      i += 1
    else
      text_pairs << text[i, 2]
      i += 2
    end
  end
  text_pairs
end
post '/aesresult' do
  action = params[:action]  # Check which button was clicked

  # Gather parameters
  text = params[:text] || ""
  key = params[:key] || ""
  key_size = params[:key_size].to_i
  mode = params[:mode] || "CBC"
  format = params[:format] || "Base64"
  iv = params[:iv]

  if action == 'encrypt'
    begin
      cipher = OpenSSL::Cipher.new("AES-#{key_size}-#{mode}")
      cipher.encrypt
      cipher.key = key.ljust(key_size / 8, "\0")  # Pad key to match size

      encrypted = cipher.update(text) + cipher.final
      @result = format == "Base64" ? Base64.encode64(encrypted) : encrypted.unpack1('H*')
      @message = "Encryption successful!"
      @back_link = '/aes'
    rescue => e
      @result = nil
      @message = "Encryption failed: #{e.message}"
    end
  elsif action == 'decrypt'
    begin
      decipher = OpenSSL::Cipher.new("AES-#{key_size}-#{mode}")
      decipher.decrypt
      decipher.key = key.ljust(key_size / 8, "\0")  # Pad key to match size
      decipher.iv = [iv].pack('H*') if mode == 'CBC' && !iv.to_s.strip.empty?

      decoded_text = format == "Base64" ? Base64.decode64(text) : [text].pack('H*')
      @result = decipher.update(decoded_text) + decipher.final
      @message = "Decryption successful!"
      @back_link = '/aes'
    rescue => e
      @result = nil
      @back_link = '/aes'
      @message = "Decryption failed: #{e.message}"
    end
  else
    @result = nil
    @message = "Invalid action!"
  end

  erb :aesresult
end

def aes_decrypt(encrypted_hex, key, iv)
  encrypted_data = [encrypted_hex].pack('H*')  # Ensure binary format conversion is correct
  cipher = OpenSSL::Cipher.new('AES-128-CBC')
  cipher.decrypt
  cipher.key = key
  cipher.iv = [iv].pack('H*')

  decrypted = cipher.update(encrypted_data) + cipher.final
  decrypted
end
# Decryption function
def aes_decrypt(encrypted_hex, key, iv)
  # Convert the hexadecimal string to binary format
  encrypted_data = [encrypted_hex].pack('H*')

  cipher = OpenSSL::Cipher.new('AES-128-CBC')
  cipher.decrypt
  cipher.key = key
  cipher.iv = [iv].pack('H*')  # Convert IV from hexadecimal to binary

  # Decrypt the data
  decrypted = cipher.update(encrypted_data) + cipher.final
  decrypted
end