import requests

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

def get_route(dpid_src, port_src, dpid_dst, port_dst):
    url = f"http://10.20.12.150:8080/wm/topology/route/{dpid_src}/{port_src}/{dpid_dst}/{port_dst}/json"
    response = requests.get(url)
    if response.status_code != 200:
        raise Exception("Error al obtener la ruta del controlador Floodlight")

    route = response.json()
    path = []

    for hop in route:
        src = hop["src-switch"]
        src_p = hop["src-port"]
        dst = hop["dst-switch"]
        dst_p = hop["dst-port"]
        path.append((src, src_p, dst, dst_p))

    return path