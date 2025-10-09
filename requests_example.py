import requests

FLOODLIGHT = "http://10.20.12.150:8080"
ROUTE_API = f"{FLOODLIGHT}/wm/topology/route"

def get_attachement_points(mac):
    url = "http://10.20.12.150:8080/wm/device/"
    response = requests.get(url)
    if response.status_code != 200:
        raise Exception("Error al conectar con el controlador Floodlight")

    devices = response.json()
    for device in devices:
        if mac.lower() in [m.lower() for m in device.get("mac", [])]:
            # Retornar el DPID y puerto del punto de conexión
            attachment = device.get("attachmentPoint", [])[0]
            return attachment["switchDPID"], attachment["port"]

    return None, None  # Si no se encuentra


def get_route(src_dpid, src_port, dst_dpid, dst_port):
    """
    Devuelve la ruta entre dos puntos de conexión (DPID + puerto) en Floodlight.
    Soporta los formatos modernos (con objetos 'port') y los clásicos.
    """
    url = f"{ROUTE_API}/{src_dpid}/{src_port}/{dst_dpid}/{dst_port}/json"
    r = requests.get(url)
    if r.status_code != 200:
        raise Exception(f"Error al obtener la ruta del controlador Floodlight ({r.status_code})")

    data = r.json()
    if not data:
        raise Exception("Floodlight devolvió una ruta vacía o nula")

    # --- Nuevo formato (lista de switches con objeto 'port':{'portNumber':X}) ---
    if isinstance(data, list) and all("switch" in d and "port" in d for d in data):
        ruta = []
        for i in range(len(data) - 1):
            # Extraer el número de puerto correctamente
            port_src = data[i]["port"].get("portNumber") if isinstance(data[i]["port"], dict) else data[i]["port"]
            port_dst = data[i + 1]["port"].get("portNumber") if isinstance(data[i + 1]["port"], dict) else data[i + 1]["port"]

            hop = {
                "src-switch": data[i]["switch"],
                "src-port": port_src,
                "dst-switch": data[i + 1]["switch"],
                "dst-port": port_dst
            }
            ruta.append(hop)
        return ruta

    # --- Formato clásico (Floodlight antiguo) ---
    elif isinstance(data, list) and all("src-switch" in d for d in data):
        return data

    else:
        raise Exception(f"Formato de ruta no reconocido: {data}")