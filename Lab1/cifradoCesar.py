import sys

def cifrado_cesar(texto, desplazamiento):
    resultado = ""
    for char in texto:
        if char.isupper():
            resultado += chr((ord(char) - 65 + desplazamiento) % 26 + 65)
        elif char.islower():
            resultado += chr((ord(char) - 97 + desplazamiento) % 26 + 97)
        else:
            resultado += char
    return resultado

if len(sys.argv) < 3:
    print(f"Uso: python3 {sys.argv[0]} \"texto\" desplazamiento")
    sys.exit(1)

texto = sys.argv[1]
desplazamiento = int(sys.argv[2])

print(cifrado_cesar(texto, desplazamiento))
