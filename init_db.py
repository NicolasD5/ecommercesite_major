from flask_bcrypt import Bcrypt
import sqlite3
from encryption import encrypt_data #Imports the encrypt_data function from encryption.py

bcrypt = Bcrypt()  #Create a Bcrypt instance

def insert_user(username, password, mobile, address): #Encrypts and inserts a new user into the database
    connection = sqlite3.connect('database.db')
    cursor = connection.cursor()

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8") #Sets variables, encrypts data and hashes the password and so it can be inserted into the database
    encrypted_mobile = encrypt_data(mobile)
    encrypted_address = encrypt_data(address)

    cursor.execute("INSERT INTO users (username, password, mobile, address) VALUES (?, ?, ?, ?)",
                   (username, hashed_password, encrypted_mobile, encrypted_address))

    connection.commit()
    connection.close()

def insert_products():
    """Insert products into the database"""
    products = [
        {
            'name': 'Gibson Les Paul Junior TV Yellow',
            'description': 'Although introduced in 1954 as a more affordable option for students and beginners, the Les Paul™ Junior has gained a reputation among seasoned professionals for its raw, unfiltered tone.',
            'price': 2449.99,
            'stock': 15,
            'image': 'gibsonlespauljuniortvyellow.jpg',
            'additional_images': [
                'gibsonlespauljuniortvyellow_1.jpg',
                'gibsonlespauljuniortvyellow_2.jpg',
                'gibsonlespauljuniortvyellow_3.jpg',
                'gibsonlespauljuniortvyellow_4.jpg',
                'gibsonlespauljuniortvyellow_5.jpg',
                'gibsonlespauljuniortvyellow_6.jpg',
                'gibsonlespauljuniortvyellow_7.jpg',
                'gibsonlespauljuniortvyellow_8.jpg'
            ] 
        },
        {
            'name': '1957 Gibson Les Paul Custom Reissue Ebony',
            'description': 'With its elegant lines and Ebony/Pearl/Gold aesthetic, the 1957 Les Paul Custom is easily one of the most iconic and beautiful guitars ever made. It features a body carved out of a single large piece of solid mahogany, unique among Les Paul models. The resulting dark mid-range tone from the body pairs perfectly with its bright-sounding solid Ebony fingerboard. All together, the pinnacle of guitar craftsmanship, design and tone. Gibson Custom Shop is proud to revive every last detail of the original "Black Beauty" for this 1957 Les Paul Custom Reissue, from the dimensions and contours to the precise inlay patterns to the entire ownership experience.',
            'price': 6899.99,
            'stock': 2,
            'image': 'gibsonlespaulcustom.jpg',
            'additional_images': [
                'gibsonlespaulcustom_1.jpg',
                'gibsonlespaulcustom_2.jpg',
                'gibsonlespaulcustom_3.jpg',
                'gibsonlespaulcustom_4.jpg',
                'gibsonlespaulcustom_5.jpg'
            ]
        },
        {
            'name': 'Gibson SG Junior Vintage Cherry',
            'description': 'The SG Junior returns to the classic design that made it relevant, played, and loved—shaping sound across generations and genres of music. Initially introduced in the early 60s as a student model, the SG Junior has been embraced by musicians ranging from students to world-renowned star performers for over 60 years.',
            'price': 2399.99,
            'stock': 9,
            'image': 'gibsonsgjunior.jpg',
            'additional_images': [
                'gibsonsgjunior_1.jpg',
                'gibsonsgjunior_2.jpg',
                'gibsonsgjunior_3.jpg',
                'gibsonsgjunior_4.jpg',
                'gibsonsgjunior_5.jpg',
                'gibsonsgjunior_6.jpg',
                'gibsonsgjunior_7.jpg'                
            ]
        },
        {
            'name': 'Gibson Les Paul Standard 50s P-90 Goldtop',
            'description': "The new Les Paul Standard returns to the classic design that made it famous, paying tribute to Gibson's Golden Era of innovation and placing authenticity at the forefront. Pairing a naturally resonant solid mahogany body with a bright, clear maple top—a combination that has shaped music since the 1950s—this instrument reflects the era when Gibson cemented its reputation for unparalleled craftsmanship and tone.",
            'price': 3899.99,
            'stock': 5,
            'image': 'gibsonlespaulstandard50p90.jpg',
            'additional_images': [
                'gibsonlespaulstandard50p90_1.jpg',
                'gibsonlespaulstandard50p90_2.jpg',
                'gibsonlespaulstandard50p90_3.jpg',
                'gibsonlespaulstandard50p90_4.jpg'                
            ]
        },
        {
            'name': '1957 Gibson Les Paul Junior Reissue Vintage Sunburst',
            'description': 'In guitar lingo, being "ruined" is when you play something so good, there is no going back to what you once had. No Gibson guitar has evoked this expression more than the Les Paul Junior. In the 1950s it was sold as a student/budget model -- as simple as a set-neck electric guitar could be. But after a while, the humble Les Paul Junior caught the ear of professional guitarists who appreciated its sonic purity and minimalist components. Gibson Custom Shop has proudly kept the recipe the same for this Historic Reissue. From the solid mahogany and hide glue construction to the vintage-style wiring, the classic Les Paul Junior is back...and ready to "ruin" you.',
            'price': 6199.99,
            'stock': 1,
            'image': '57lespauljuniorsunburstnew.jpg',
            'additional_images': [
                '57lespauljuniorsunburstnew_1.jpg',
                '57lespauljuniorsunburstnew_2.jpg',
                '57lespauljuniorsunburstnew_3.jpg',
                '57lespauljuniorsunburstnew_4.jpg',
                '57lespauljuniorsunburstnew_5.jpg',
                '57lespauljuniorsunburstnew_6.jpg'
            ]
        },
        {
            'name': 'Gibson ES-335 Sixties Cherry',
            'description': 'From its inaugural appearance in 1958, the Gibson ES-335 has remained an unmatched standard, prized for its versatility and rich tonal palette. Its laminated maple/poplar/maple body and solid maple centerblock help control feedback while retaining the airy resonance that has made the ES-335 beloved by players across genres—from warm jazz to articulate rock, and all sonic stops in between.',
            'price': 5299.99,
            'stock': 7,
            'image': 'gibsones335cherry.jpg',
            'additional_images': [
                'gibsones335cherry_1.jpg',
                'gibsones335cherry_2.jpg',
                'gibsones335cherry_3.jpg',
                'gibsones335cherry_4.jpg',
                'gibsones335cherry_5.jpg',
                'gibsones335cherry_6.jpg',
                'gibsones335cherry_7.jpg',
                'gibsones335cherry_8.jpg'
            ]
        },
        {
            'name': '1958 Gibson Les Paul Junior Double Cut TV Yellow',
            'description': '1958 was a monumental year for Gibson in which a whole new lineup of now-famous models was introduced. One of them was the redesigned “double cutaway” Les Paul™ Junior, which has since found its place in music history as a favorite of hard rock musicians, especially when they have a broken-in feel like this one.',
            'price': 4799.99,
            'stock': 4,
            'image': 'gibsonlespauljuniordoublecut.jpg',
            'additional_images': [
                'gibsonlespauljuniordoublecut_1.jpg',
                'gibsonlespauljuniordoublecut_2.jpg',
                'gibsonlespauljuniordoublecut_3.jpg',
                'gibsonlespauljuniordoublecut_4.jpg',
                'gibsonlespauljuniordoublecut_5.jpg',
                'gibsonlespauljuniordoublecut_6.jpg'
            ]
        },
        {
            'name': '1964 Gibson SG Bigsby Cherry',
            'description': 'Introduced in 1961 as a successor to the original Les Paul™, the Gibson SG™ quickly became a rock icon with its aggressive tone, lightweight body, and double-cutaway design. This rare example of a 1964 SG Standard features an original Bigsby® B5 “Horseshoe” vibrato and Bigsby Dogbone bridge—an uncommon bridge/tailpiece configuration for an SG from this era.',
            'price': 38699.99,
            'stock': 1,
            'image': 'gibsonsgbigsby.jpg',
            'additional_images': [
                'gibsonsgbigsby_1.jpg',
                'gibsonsgbigsby_2.jpg',
                'gibsonsgbigsby_3.jpg',
                'gibsonsgbigsby_4.jpg',
                'gibsonsgbigsby_5.jpg',
                'gibsonsgbigsby_6.jpg',
                'gibsonsgbigsby_7.jpg'
            ]
        },
        {
            'name': 'Gibson Les Paul Custom Andromeda Black',
            'description': 'This Gibson Custom Select Les Paul™ Custom in Andromeda Black is a unique spin on a classic model from the Modern Collection. The standout features of this special guitar are the Andromeda Black finish and the chrome hardware.',
            'price': 7299.99,
            'stock': 3,
            'image': 'gibsonlespaulcustomadromedablack.jpg',
            'additional_images': [
                'gibsonlespaulcustomadromedablack_1.jpg',
                'gibsonlespaulcustomadromedablack_2.jpg',
                'gibsonlespaulcustomadromedablack_3.jpg',
                'gibsonlespaulcustomadromedablack_4.jpg',
                'gibsonlespaulcustomadromedablack_5.jpg',
                'gibsonlespaulcustomadromedablack_6.jpg'                
            ]
        },
        {
            'name': 'Gibson Les Paul Junior Ebony',
            'description': 'Although introduced in 1954 as a more affordable option for students and beginners, the Les Paul™ Junior has gained a reputation among seasoned professionals for its raw, unfiltered tone.',
            'price': 2449.99,
            'stock': 13,
            'image': 'gibsonlespauljuniorebony.jpg',
            'additional_images': [
                'gibsonlespauljuniorebony_1.jpg',
                'gibsonlespauljuniorebony_2.jpg',
                'gibsonlespauljuniorebony_3.jpg',
                'gibsonlespauljuniorebony_4.jpg',
                'gibsonlespauljuniorebony_5.jpg',
                'gibsonlespauljuniorebony_6.jpg',
                'gibsonlespauljuniorebony_7.jpg',
                'gibsonlespauljuniorebony_8.jpg'
            ]
        },
        {
            'name': 'Gibson SG Standard Ebony',
            'description': 'The Gibson SG Standard rocks the classic looks and features associated with the late-60s-style SG™ models so many players love. A solid mahogany body provides the backbone for singing sustain, while a rounded profile mahogany neck and bound rosewood fingerboard deliver a comfortable playing experience across all 22 frets.',
            'price': 2699.99,
            'stock': 8,
            'image': 'gibsonsgstandardebony.jpg',
            'additional_images': [
                'gibsonsgstandardebony_1.jpg',
                'gibsonsgstandardebony_2.jpg',
                'gibsonsgstandardebony_3.jpg',
                'gibsonsgstandardebony_4.jpg'
            ]
        },
        {
            'name': 'Gibson SG Custom Ebony',
            'description': 'This recent Custom Shop addition takes the engine and aesthetics of the iconic Les Paul Custom and applies them to the SG platform. The result is a huge-sounding, fast-playing and classy-looking instrument that will bring out the best in any player.',
            'price': 6999.99,
            'stock': 3,
            'image': 'gibsonsgcustomebony.jpg',
            'additional_images': [
                'gibsonsgcustomebony_1.jpg',
                'gibsonsgcustomebony_2.jpg',
                'gibsonsgcustomebony_3.jpg',
                'gibsonsgcustomebony_4.jpg',
                'gibsonsgcustomebony_5.jpg',
                'gibsonsgcustomebony_6.jpg',
                'gibsonsgcustomebony_7.jpg',
                'gibsonsgcustomebony_8.jpg',
                'gibsonsgcustomebony_9.jpg',
                'gibsonsgcustomebony_10.jpg'
            ]
        },
        {
            'name': '1964 Gibson SG Special Classic White',
            'description': 'As the choice of rock n roll legends for decades, the original SG™ Special represented simplicity, versatility, and monster tone. This Historic recreation is a clone of the cherished vintage originals with all the modern playability and reliability you expect from the Gibson Custom Shop.',
            'price': 5999.99,
            'stock': 2,
            'image': 'gibsonsgspecialwhite.jpg',
            'additional_images': [
                'gibsonsgspecialwhite_1.jpg',
                'gibsonsgspecialwhite_2.jpg',
                'gibsonsgspecialwhite_3.jpg',
                'gibsonsgspecialwhite_4.jpg',
                'gibsonsgspecialwhite_5.jpg',
                'gibsonsgspecialwhite_6.jpg',
                'gibsonsgspecialwhite_7.jpg',
                'gibsonsgspecialwhite_8.jpg'
            ]
        },
        {
            'name': 'Gibson Les Paul Standard 50s Ebony',
            'description': 'The new Les Paul Standard 50s Plain Top returns to the classic design that made it relevant, played, and loved – shaping sound across generations and genres of music.',
            'price': 3899.99,
            'stock': 6,
            'image': 'gibsonlespaulstandard50sebony.jpg',
            'additional_images': [
                'gibsonlespaulstandard50sebony_1.jpg',
                'gibsonlespaulstandard50sebony_2.jpg',
                'gibsonlespaulstandard50sebony_3.jpg',
                'gibsonlespaulstandard50sebony_4.jpg',
                'gibsonlespaulstandard50sebony_5.jpg',
                'gibsonlespaulstandard50sebony_6.jpg'
            ]
        },
        {
            'name': 'Gibson ES-335 Satin Vintage Natural',
            'description': 'The Gibson ES-335 DOT is the cornerstone of the Gibson ES line-up. From its inaugural appearance in 1958, the Gibson ES-335 immediately set an unmatched standard.',
            'price': 4199.99,
            'stock': 4,
            'image': 'gibsones335satinvintagenatural.jpg',
            'additional_images': [
                'gibsones335satinvintagenatural_1.jpg',
                'gibsones335satinvintagenatural_2.jpg',
                'gibsones335satinvintagenatural_3.jpg',
                'gibsones335satinvintagenatural_4.jpg',
                'gibsones335satinvintagenatural_5.jpg',
                'gibsones335satinvintagenatural_6.jpg',
                'gibsones335satinvintagenatural_7.jpg',
                'gibsones335satinvintagenatural_8.jpg',
                'gibsones335satinvintagenatural_9.jpg'
            ]
        },
    ]
    
    connection = sqlite3.connect('database.db')
    cursor = connection.cursor()
    
    for product in products:
        try:
            cursor.execute("""
                INSERT INTO products (name, description, price, stock, image, additional_images)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                product['name'],
                product['description'],
                product['price'],
                product['stock'],
                product['image'],
                ','.join(product.get('additional_images', []))  # Join image paths with commas
            ))
        except Exception as e:
            print(f"Error adding product {product['name']}: {e}")
    
    connection.commit()
    connection.close()

# Initialise database and insert products
if __name__ == "__main__":
    try:
        # Create fresh database
        connection = sqlite3.connect('database.db')
        print("Created database connection")
        
        # Create tables
        with open('schema.sql') as f:
            connection.executescript(f.read())
        print("Created tables")
        
        # Insert products
        insert_products()
        
        # Verify products were inserted
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM products")
        count = cursor.fetchone()[0]
        print(f"Successfully inserted {count} products")
        
        connection.close()
        
    except Exception as e:
        print(f"Database initialisation error: {e}")