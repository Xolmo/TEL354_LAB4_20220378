class Alumno:
    def __init__(self, nombre, pc):
        self.nombre = nombre
        self.pc = pc  # Dirección MAC

class Servicio:
    def __init__(self, nombre, protocolo, puerto):
        self.nombre = nombre
        self.protocolo = protocolo
        self.puerto = puerto

class Servidor:
    def __init__(self, nombre, direccion_ip):
        self.nombre = nombre
        self.direccion_ip = direccion_ip
        self.servicios = []  # Lista de objetos Servicio

    def agregar_servicio(self, servicio):
        self.servicios.append(servicio)

class Curso:
    def __init__(self, nombre, estado):
        self.nombre = nombre
        self.estado = estado
        self.alumnos = []     # Lista de objetos Alumno
        self.servidores = []  # Lista de objetos Servidor

    def agregar_alumno(self, alumno):
        self.alumnos.append(alumno)

    def remover_alumno(self, nombre_alumno):
        self.alumnos = [a for a in self.alumnos if a.nombre != nombre_alumno]

    def anadir_servidor(self, servidor):
        self.servidores.append(servidor)

# Función principal
def main():
    # Crear alumnos
    alumno1 = Alumno("Telequito", "00:1A:2B:3C:4D:5E")
    alumno2 = Alumno("Mathi", "11:22:33:44:55:66")

    # Crear servicios
    servicio_web = Servicio("HTTP", "TCP", 80)
    servicio_dns = Servicio("DNS", "UDP", 53)

    # Crear servidor y añadir servicios
    servidor1 = Servidor("Servidor1", "192.168.1.10")
    servidor1.agregar_servicio(servicio_web)
    servidor1.agregar_servicio(servicio_dns)

    # Crear curso y añadir alumnos y servidor
    curso_redes = Curso("Ingeniería de Redes", "Activo")
    curso_redes.agregar_alumno(alumno1)
    curso_redes.agregar_alumno(alumno2)
    curso_redes.anadir_servidor(servidor1)

    # Remover un alumno
    curso_redes.remover_alumno("Mathi")

    # Mostrar datos finales
    print("Curso:", curso_redes.nombre)
    print("Estado:", curso_redes.estado)
    print("Alumnos:")
    for a in curso_redes.alumnos:
        print(f"  - {a.nombre} ({a.pc})")
    print("Servidores:")
    for s in curso_redes.servidores:
        print(f"  - {s.nombre} ({s.direccion_ip})")
        for serv in s.servicios:
            print(f"     * Servicio: {serv.nombre} ({serv.protocolo}:{serv.puerto})")

# -----------------------------
# Ejecución
# -----------------------------
if __name__ == "__main__":
    main()
