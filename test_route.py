from requests_example import get_route
from appSDN import get_host_info_by_mac, get_host_info_by_ip

# Datos de los hosts
mac_alumno = "fa:16:3e:37:51:df"
ip_servidor = "10.0.0.3"

# 1. Obtener punto de conexión del alumno
dpid_src, port_src, ips_src, _ = get_host_info_by_mac(mac_alumno)
print(f"Alumno conectado en switch {dpid_src}, puerto {port_src}")

# 2. Obtener punto de conexión del servidor
dpid_dst, port_dst, ips_dst, _ = get_host_info_by_ip(ip_servidor)
print(f"Servidor conectado en switch {dpid_dst}, puerto {port_dst}")

# 3. Obtener ruta
ruta = get_route(dpid_src, port_src, dpid_dst, port_dst)

# 4. Mostrar ruta
print("\nRuta encontrada:")
for hop in ruta:
    if isinstance(hop, dict):
        print(f"{hop.get('src-switch')}:{hop.get('src-port')} → {hop.get('dst-switch')}:{hop.get('dst-port')}")
    elif isinstance(hop, (list, tuple)) and len(hop) >= 4:
        print(f"{hop[0]}:{hop[1]} → {hop[2]}:{hop[3]}")
    else:
        print(hop)
