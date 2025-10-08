import yaml

def main():
    # Abrir y cargar el archivo YAML
    with open("datos.yaml", "r") as archivo:
        datos = yaml.safe_load(archivo)
    # Imprimir lista de servidores
        print("Nombres de servidores:")
        for servidor in datos["servidores"]:
            print(f"- {servidor['nombre']}")

if __name__ == "__main__":
    main()