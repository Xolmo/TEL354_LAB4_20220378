# ========================================================
# appSDN.py — Control de red SDN (modo proactivo con CRUD + Conexiones + Flows)
# ========================================================

import yaml
import requests
import time
from clases import Alumno, Curso, Servidor, Servicio
from requests_example import get_attachement_points, get_route

FLOODLIGHT = "http://10.20.12.150:8080"
STATIC_FLOW_PUSHER = f"{FLOODLIGHT}/wm/staticflowpusher/json"
DEVICE_API = f"{FLOODLIGHT}/wm/device/"
TIMEOUT = 5


# ========================================================
# HELPERS FLOODLIGHT
# ========================================================
def _http_post(url, payload):
    r = requests.post(url, json=payload, timeout=TIMEOUT)
    r.raise_for_status()
    return r.json() if r.text else {}

def _http_delete(url, payload=None):
    if payload is not None:
        r = requests.delete(url, json=payload, timeout=TIMEOUT)
    else:
        r = requests.delete(url, timeout=TIMEOUT)
    # some floodlight builds return 200 with empty body
    if r.status_code not in (200, 204):
        raise RuntimeError(f"DELETE failed {r.status_code}: {r.text}")
    return True

def get_host_info_by_mac(mac):
    """Devuelve (dpid, port, ipv4_list, mac_list) para un host a partir de su MAC."""
    r = requests.get(DEVICE_API, timeout=TIMEOUT)
    r.raise_for_status()
    for dev in r.json():
        macs = [m.lower() for m in dev.get("mac", [])]
        if mac.lower() in macs:
            ap = dev.get("attachmentPoint", [])
            ipv4 = dev.get("ipv4", [])
            if ap:
                return ap[0].get("switchDPID"), ap[0].get("port"), ipv4, dev.get("mac", [])
    return None, None, [], []

def get_host_info_by_ip(ipv4):
    """Devuelve (dpid, port, ipv4_list, mac_list) para un host a partir de su IP."""
    r = requests.get(DEVICE_API, timeout=TIMEOUT)
    r.raise_for_status()
    for dev in r.json():
        ips = [i for i in dev.get("ipv4", [])]
        if ipv4 in ips:
            ap = dev.get("attachmentPoint", [])
            if ap:
                return ap[0].get("switchDPID"), ap[0].get("port"), ips, dev.get("mac", [])
    return None, None, [], []

def ip_proto_number(proto_name: str) -> int:
    p = proto_name.strip().upper()
    if p == "TCP": return 6
    if p == "UDP": return 17
    if p == "ICMP": return 1
    raise ValueError(f"Protocolo no soportado: {proto_name}")


# ========================================================
# IMPORTAR / EXPORTAR YAML
# ========================================================
def importar_datos(nombre_archivo):
    with open(nombre_archivo, "r") as f:
        datos = yaml.safe_load(f)

    alumnos, cursos, servidores = [], [], []
    codigo_to_alumno = {}

    # --- Alumnos ---
    for a in datos.get("alumnos", []):
        # clases.Alumno solo tiene (nombre, pc) -> guardamos MAC en pc
        alumno = Alumno(a.get("nombre"), a.get("mac"))
        # añadimos dinámicamente el atributo codigo si viene
        if "codigo" in a:
            setattr(alumno, "codigo", a["codigo"])
            codigo_to_alumno[a["codigo"]] = alumno
        alumnos.append(alumno)

    # --- Servidores ---
    for s in datos.get("servidores", []):
        serv = Servidor(s["nombre"], s["ip"])
        for svc in s.get("servicios", []):
            serv.agregar_servicio(Servicio(svc["nombre"], svc["protocolo"], svc["puerto"]))
        servidores.append(serv)

    # --- Cursos ---
    for c in datos.get("cursos", []):
        curso = Curso(c.get("nombre") or c.get("codigo", "CURSO"), c.get("estado", "INACTIVO"))
        # lista de codigos de alumno
        codigos = c.get("alumnos", []) or []
        curso.alumnos = []
        for cod in codigos:
            al = codigo_to_alumno.get(cod)
            if al:
                curso.agregar_alumno(al)

        # servidores y servicios_permitidos por curso
        curso.servidores = []
        srv_permitidos = {}
        for s in c.get("servidores", []) or []:
            nombre_srv = s.get("nombre")
            srv_obj = next((sv for sv in servidores if sv.nombre == nombre_srv), None)
            if srv_obj:
                curso.anadir_servidor(srv_obj)
                permit = [p for p in (s.get("servicios_permitidos") or [])]
                srv_permitidos[nombre_srv] = permit
        # lo agregamos como atributo dinámico
        setattr(curso, "servicios_permitidos", srv_permitidos)

        cursos.append(curso)

    print(f"Importados: {len(alumnos)} alumnos, {len(cursos)} cursos, {len(servidores)} servidores.")
    return alumnos, cursos, servidores


def exportar_datos(nombre_archivo, alumnos, cursos, servidores):
    datos = {
        "alumnos": [
            {"nombre": a.nombre, "mac": a.pc, **({"codigo": getattr(a, "codigo")} if hasattr(a, "codigo") else {})}
            for a in alumnos
        ],
        "cursos": [],
        "servidores": [
            {
                "nombre": s.nombre,
                "ip": s.direccion_ip,
                "servicios": [{"nombre": svc.nombre, "protocolo": svc.protocolo, "puerto": svc.puerto}
                              for svc in s.servicios]
            }
            for s in servidores
        ]
    }

    for c in cursos:
        item = {
            "nombre": c.nombre,
            "estado": c.estado,
            "alumnos": [getattr(a, "codigo", a.nombre) for a in c.alumnos],
            "servidores": []
        }
        sp = getattr(c, "servicios_permitidos", {})
        for srv in c.servidores:
            item["servidores"].append({
                "nombre": srv.nombre,
                "servicios_permitidos": sp.get(srv.nombre, [])
            })
        datos["cursos"].append(item)

    with open(nombre_archivo, "w") as f:
        yaml.safe_dump(datos, f, sort_keys=False)
    print(f"Exportado a {nombre_archivo}")


# ========================================================
# AUTORIZACIÓN
# ========================================================
def alumno_autorizado(alumno, servidor, servicio, cursos):
    svc_name = servicio.strip().lower()
    for c in cursos:
        if c.estado.upper() != "DICTANDO":
            continue
        if not any(a is alumno for a in c.alumnos):
            continue
        if servidor not in c.servidores:
            continue
        permitidos = getattr(c, "servicios_permitidos", {})
        lst = [s.lower() for s in permitidos.get(servidor.nombre, [])]
        if svc_name in lst:
            return True
    return False


# ========================================================
# FLOW PUSHER (instalación/eliminación de flows)
# ========================================================
def push_flow(flow_name, switch_dpid, match, out_port, priority=32768):
    body = {
        "switch": switch_dpid,
        "name": flow_name,
        "cookie": "0",
        "priority": str(priority),
        "active": "true",
        **match,
        "actions": f"output={out_port}"
    }
    # Floodlight staticflowpusher
    r = requests.post(STATIC_FLOW_PUSHER, json=body, timeout=TIMEOUT)
    if r.status_code not in (200, 201, 204):
        raise RuntimeError(f"push_flow {flow_name} failed: {r.status_code} {r.text}")
    return True

def delete_flow(flow_name):
    # Algunos builds aceptan DELETE con {"name":...}
    try:
        _http_delete(STATIC_FLOW_PUSHER, {"name": flow_name})
        return True
    except Exception:
        pass
    # Fallback: usar endpoint /wm/staticflowpusher/clear/<switch>
    # (No siempre está disponible: lo omitimos por seguridad)
    return False


# ========================================================
# CONSTRUCCIÓN DE RUTA Y FLOWS
# ========================================================
def _install_ip_flows_for_hop(switch, in_port, out_port, src_ip, dst_ip, proto_num, l4_dst_port, flow_tag):
    # IPv4 forward (host -> server)
    match_fwd = {
        "in_port": str(in_port),
        "eth_type": "0x0800",
        "ipv4_src": f"{src_ip}/32",
        "ipv4_dst": f"{dst_ip}/32",
        "ip_proto": str(proto_num),
    }
    if proto_num == 6:
        match_fwd["tcp_dst"] = str(l4_dst_port)
    elif proto_num == 17:
        match_fwd["udp_dst"] = str(l4_dst_port)
    push_flow(f"{flow_tag}-ip-fwd", switch, match_fwd, out_port, priority=40000)

    # IPv4 reverse (server -> host)
    match_rev = {
        "in_port": str(out_port),
        "eth_type": "0x0800",
        "ipv4_src": f"{dst_ip}/32",
        "ipv4_dst": f"{src_ip}/32",
        "ip_proto": str(proto_num),
    }
    if proto_num == 6:
        match_rev["tcp_src"] = str(l4_dst_port)
    elif proto_num == 17:
        match_rev["udp_src"] = str(l4_dst_port)
    push_flow(f"{flow_tag}-ip-rev", switch, match_rev, in_port, priority=40000)

def _install_arp_flows_for_hop(switch, in_port, out_port, flow_tag):
    # ARP in both directions (no IP match)
    match_arp_fwd = {
        "in_port": str(in_port),
        "eth_type": "0x0806",
    }
    push_flow(f"{flow_tag}-arp-fwd", switch, match_arp_fwd, out_port, priority=45000)

    match_arp_rev = {
        "in_port": str(out_port),
        "eth_type": "0x0806",
    }
    push_flow(f"{flow_tag}-arp-rev", switch, match_arp_rev, in_port, priority=45000)

def build_route(alumno, servidor, servicio):
    # Resolver IPs y puntos de acceso
    dpid_src, port_src, ips_src, _ = get_host_info_by_mac(alumno.pc)
    if not dpid_src or not port_src:
        raise RuntimeError("No se encontró attachment point del alumno")

    # intentar encontrar el servidor por IP conocida (propiedad del objeto servidor)
    dpid_dst, port_dst, ips_dst, _ = get_host_info_by_ip(servidor.direccion_ip)
    if not dpid_dst or not port_dst:
        raise RuntimeError("No se encontró attachment point del servidor")

    # Determinar IPs (toma la primera del host si no hay otra especificada)
    ip_src = ips_src[0] if ips_src else None
    ip_dst = servidor.direccion_ip  # ya la tenemos
    if not ip_src or not ip_dst:
        raise RuntimeError("No se pudieron determinar las IPs del host o servidor")

    # Determinar protocolo y puerto L4 a partir del servicio
    svc_obj = next((s for s in servidor.servicios if s.nombre.lower() == servicio.lower()), None)
    if not svc_obj:
        raise RuntimeError("El servidor no expone el servicio solicitado")
    proto_num = ip_proto_number(svc_obj.protocolo)
    l4_dst_port = int(svc_obj.puerto)

    # Obtener ruta
    ruta = get_route(dpid_src, port_src, dpid_dst, port_dst)

    # Instalar flows por cada salto
    created = []
    for i, hop in enumerate(ruta):
        sw = hop["src-switch"] if isinstance(hop, dict) else hop[0]
        in_p = hop["src-port"] if isinstance(hop, dict) else hop[1]
        out_p = hop["dst-port"] if isinstance(hop, dict) else hop[3]

        tag = f"{alumno.nombre}-{servidor.nombre}-hop{i}"
        _install_ip_flows_for_hop(sw, in_p, out_p, ip_src, ip_dst, proto_num, l4_dst_port, tag)
        _install_arp_flows_for_hop(sw, in_p, out_p, tag)
        created.append(tag)

    print(f"Instalada ruta con {len(ruta)} saltos entre {alumno.nombre} → {servidor.nombre}")
    return created


# ========================================================
# CRUD Y SUBMENÚS
# ========================================================
def menu_alumnos(alumnos):
    while True:
        print("\n--- GESTIÓN DE ALUMNOS ---")
        print("1) Crear alumno")
        print("2) Listar alumnos")
        print("3) Actualizar alumno")
        print("4) Eliminar alumno")
        print("5) Volver")
        op = input("Seleccione: ").strip()
        if op == "1":
            nombre = input("Nombre: ")
            mac = input("MAC: ")
            alumno = Alumno(nombre, mac)
            # opcional: código
            cod = input("Código (opcional): ").strip()
            if cod:
                setattr(alumno, "codigo", cod)
            alumnos.append(alumno)
            print("Alumno creado.")
        elif op == "2":
            if not alumnos:
                print("No hay alumnos.")
            for a in alumnos:
                cod = getattr(a, "codigo", "")
                cod_str = f" | código: {cod}" if cod else ""
                print(f"- {a.nombre} (MAC {a.pc}){cod_str}")
        elif op == "3":
            nombre = input("Alumno a actualizar: ")
            a = next((x for x in alumnos if x.nombre == nombre), None)
            if not a:
                print("No encontrado.")
                continue
            nuevo = input("Nuevo nombre (Enter para mantener): ").strip()
            mac = input("Nueva MAC (Enter para mantener): ").strip()
            cod = input("Nuevo código (Enter para mantener): ").strip()
            if nuevo: a.nombre = nuevo
            if mac: a.pc = mac
            if cod: setattr(a, "codigo", cod)
            print("Actualizado.")
        elif op == "4":
            nombre = input("Alumno a eliminar: ")
            alumnos[:] = [x for x in alumnos if x.nombre != nombre]
            print("Eliminado.")
        elif op == "5":
            break
        else:
            print("Opción inválida.")


def menu_cursos(cursos, servidores, alumnos):
    while True:
        print("\n--- GESTIÓN DE CURSOS ---")
        print("1) Crear curso")
        print("2) Listar cursos")
        print("3) Actualizar estado")
        print("4) Gestionar matrícula")
        print("5) Gestionar servidores/servicios permitidos")
        print("6) Eliminar curso")
        print("7) Volver")
        op = input("Seleccione: ").strip()
        if op == "1":
            nombre = input("Nombre: ")
            estado = input("Estado (DICTANDO/INACTIVO): ").strip() or "INACTIVO"
            c = Curso(nombre, estado)
            setattr(c, "servicios_permitidos", {})
            cursos.append(c)
            print("Curso creado.")
        elif op == "2":
            if not cursos:
                print("No hay cursos.")
            for c in cursos:
                sp = getattr(c, "servicios_permitidos", {})
                print(f"- {c.nombre} ({c.estado}) | Alumnos: {len(c.alumnos)} | Servidores: {len(c.servidores)}")
                for srv in c.servidores:
                    print(f"   * {srv.nombre} → permitidos: {sp.get(srv.nombre, [])}")
        elif op == "3":
            nombre = input("Curso a actualizar: ")
            c = next((x for x in cursos if x.nombre == nombre), None)
            if not c:
                print("No encontrado.")
                continue
            estado = input("Nuevo estado: ").strip()
            if estado:
                c.estado = estado
                print("Estado actualizado.")
        elif op == "4":
            nombre = input("Curso: ")
            c = next((x for x in cursos if x.nombre == nombre), None)
            if not c:
                print("No encontrado.")
                continue
            print("1) Matricular alumno")
            print("2) Retirar alumno")
            sub = input("Seleccione: ").strip()
            if sub == "1":
                nombre_al = input("Alumno a matricular: ")
                a = next((x for x in alumnos if x.nombre == nombre_al), None)
                if a and a not in c.alumnos:
                    c.agregar_alumno(a)
                    print("Alumno matriculado.")
                else:
                    print("Alumno no encontrado o ya matriculado.")
            elif sub == "2":
                nombre_al = input("Alumno a retirar: ")
                c.alumnos = [x for x in c.alumnos if x.nombre != nombre_al]
                print("Retirado")
        elif op == "5":
            nombre = input("Curso: ")
            c = next((x for x in cursos if x.nombre == nombre), None)
            if not c:
                print("No encontrado.")
                continue
            sp = getattr(c, "servicios_permitidos", {})
            print("1) Agregar servidor al curso")
            print("2) Quitar servidor del curso")
            print("3) Agregar servicio permitido")
            print("4) Quitar servicio permitido")
            sub = input("Seleccione: ").strip()
            if sub == "1":
                srv_name = input("Servidor a agregar: ")
                srv = next((s for s in servidores if s.nombre == srv_name), None)
                if srv and srv not in c.servidores:
                    c.anadir_servidor(srv)
                    sp.setdefault(srv.nombre, [])
                    print("Servidor agregado al curso.")
                else:
                    print("Servidor no encontrado o ya presente.")
            elif sub == "2":
                srv_name = input("Servidor a quitar: ")
                c.servidores = [s for s in c.servidores if s.nombre != srv_name]
                sp.pop(srv_name, None)
                print("Servidor quitado del curso.")
            elif sub == "3":
                srv_name = input("Servidor: ")
                servicio = input("Servicio permitido a agregar (ej. ssh/web): ").strip()
                sp.setdefault(srv_name, [])
                if servicio not in sp[srv_name]:
                    sp[srv_name].append(servicio)
                    print("Servicio permitido agregado.")
                else:
                    print("Ya estaba permitido.")
            elif sub == "4":
                srv_name = input("Servidor: ")
                servicio = input("Servicio permitido a quitar: ").strip()
                if srv_name in sp and servicio in sp[srv_name]:
                    sp[srv_name].remove(servicio)
                    print("Servicio permitido quitado.")
                else:
                    print("No existía ese permiso.")
            setattr(c, "servicios_permitidos", sp)
        elif op == "6":
            nombre = input("Curso a eliminar: ")
            cursos[:] = [x for x in cursos if x.nombre != nombre]
            print("Eliminado (si existía).")
        elif op == "7":
            break
        else:
            print("Opción inválida.")


def menu_servidores(servidores):
    while True:
        print("\n--- GESTIÓN DE SERVIDORES ---")
        print("1) Crear servidor")
        print("2) Listar servidores")
        print("3) Actualizar servidor")
        print("4) Eliminar servidor")
        print("5) Gestionar servicios del servidor")
        print("6) Volver")
        op = input("Seleccione: ").strip()
        if op == "1":
            nombre = input("Nombre: ")
            ip = input("IP: ")
            servidores.append(Servidor(nombre, ip))
            print("Servidor creado.")
        elif op == "2":
            if not servidores:
                print("No hay servidores.")
            for s in servidores:
                print(f"- {s.nombre} ({s.direccion_ip})")
                for svc in s.servicios:
                    print(f"   * {svc.nombre} ({svc.protocolo}:{svc.puerto})")
        elif op == "3":
            nombre = input("Servidor a actualizar: ")
            s = next((x for x in servidores if x.nombre == nombre), None)
            if not s:
                print("No encontrado.")
                continue
            nuevo = input("Nuevo nombre (Enter para mantener): ").strip()
            ip = input("Nueva IP (Enter para mantener): ").strip()
            if nuevo: s.nombre = nuevo
            if ip: s.direccion_ip = ip
            print("Actualizado.")
        elif op == "4":
            nombre = input("Servidor a eliminar: ")
            servidores[:] = [x for x in servidores if x.nombre != nombre]
            print("Eliminado (si existía).")
        elif op == "5":
            nombre = input("Servidor a gestionar: ")
            s = next((x for x in servidores if x.nombre == nombre), None)
            if not s:
                print("No encontrado.")
                continue
            while True:
                print(f"\n--- SERVICIOS EN {s.nombre} ---")
                print("1) Agregar servicio")
                print("2) Listar servicios")
                print("3) Eliminar servicio")
                print("4) Volver")
                sub = input("Seleccione: ").strip()
                if sub == "1":
                    nombre_svc = input("Nombre del servicio (ej. ssh/web): ").strip()
                    proto = input("Protocolo (TCP/UDP): ").strip()
                    puerto = int(input("Puerto: "))
                    s.agregar_servicio(Servicio(nombre_svc, proto, puerto))
                    print("Servicio agregado.")
                elif sub == "2":
                    if not s.servicios:
                        print("No hay servicios.")
                    for svc in s.servicios:
                        print(f"- {svc.nombre} ({svc.protocolo}:{svc.puerto})")
                elif sub == "3":
                    nombre_svc = input("Servicio a eliminar: ").strip()
                    s.servicios = [sv for sv in s.servicios if sv.nombre != nombre_svc]
                    print("Servicio eliminado (si existía).")
                elif sub == "4":
                    break
        elif op == "6":
            break
        else:
            print("Opción inválida.")


# ========================================================
# SUBMENÚ CONEXIONES 
# ========================================================
def menu_conexiones(alumnos, cursos, servidores):
    while True:
        print("\n--- GESTIÓN DE CONEXIONES ---")
        print("1) Crear conexión (instala flows)")
        print("2) Eliminar flows por prefijo de nombre (best-effort)")
        print("3) Volver")
        op = input("Seleccione: ").strip()
        if op == "1":
            nombre_al = input("Alumno: ").strip()
            alumno = next((a for a in alumnos if a.nombre == nombre_al), None)
            if not alumno:
                print("Alumno no encontrado.")
                continue

            nombre_srv = input("Servidor: ").strip()
            servidor = next((s for s in servidores if s.nombre == nombre_srv), None)
            if not servidor:
                print("Servidor no encontrado.")
                continue

            servicio = input("Servicio (ej. ssh/web): ").strip()

            # Políticas
            if not alumno_autorizado(alumno, servidor, servicio, cursos):
                print("Acceso denegado según las políticas (curso DICTANDO + servidor + servicio permitido).")
                continue

            try:
                tags = build_route(alumno, servidor, servicio)
                print("Flows instalados. Prefijo de nombres:", f"{alumno.nombre}-{servidor.nombre}-")
            except Exception as e:
                print(f"Error al crear conexión: {e}")

        elif op == "2":
            pref = input("Ingrese prefijo de nombre de flows (ej. Alumno-Servidor-): ").strip()
            print("Eliminación best-effort: Debe conocer los nombres exactos si su Floodlight no soporta wildcard.")
            print("Ingrese los nombres exactos (uno por línea). Fin con línea vacía.")
            names = []
            while True:
                n = input("> ").strip()
                if not n:
                    break
                names.append(n)
            for n in names:
                ok = delete_flow(n)
                print(f"- {n}: {'OK' if ok else 'No se pudo (verifique soporte DELETE)'}")
        elif op == "3":
            break
        else:
            print("Opción inválida.")


# ========================================================
# MENÚ PRINCIPAL
# ========================================================
def menu(alumnos, cursos, servidores):
    while True:
        print("\n=== MENÚ PRINCIPAL ===")
        print("1) Importar YAML")
        print("2) Exportar YAML")
        print("3) Cursos")
        print("4) Alumnos")
        print("5) Servidores")
        print("6) Conexiones")
        print("7) Salir")
        op = input("Seleccione: ").strip()
        if op == "1":
            archivo = input("Archivo YAML: ").strip()
            try:
                new_al, new_cu, new_se = importar_datos(archivo)
                alumnos[:] = new_al
                cursos[:] = new_cu
                servidores[:] = new_se
            except Exception as e:
                print(f"Error al importar: {e}")
        elif op == "2":
            archivo = input("Archivo destino YAML: ").strip()
            try:
                exportar_datos(archivo, alumnos, cursos, servidores)
            except Exception as e:
                print(f"Error al exportar: {e}")
        elif op == "3":
            menu_cursos(cursos, servidores, alumnos)
        elif op == "4":
            menu_alumnos(alumnos)
        elif op == "5":
            menu_servidores(servidores)
        elif op == "6":
            menu_conexiones(alumnos, cursos, servidores)
        elif op == "7":
            print("Cerrando aplicación SDN")
            break
        else:
            print("Opción inválida.")


# ========================================================
# MAIN
# ========================================================
def main():
    alumnos, cursos, servidores = [], [], []
    menu(alumnos, cursos, servidores)

if __name__ == "__main__":
    main()
