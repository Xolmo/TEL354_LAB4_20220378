#!/usr/bin/python
import requests
from prettytable import PrettyTable

# DEFINE VARIABLES
controller_ip = '10.20.12.150' # UNCOMMENT AND EDIT THIS
target_api = '/wm/core/controller/switches/json' # UNCOMMENT AND EDIT THIS
headers = {'Content-type': 'application/json','Accept': 'application/json'}
url = f'http://{controller_ip}:8080/{target_api}'
response = requests.get(url=url, headers=headers)

if response.status_code == 200:
    # SUCCESSFUL REQUEST
    print('SUCCESSFUL REQUEST | STATUS: 200')
    data = response.json()
    table = PrettyTable(data[0].keys())
    for row in data:
        table.add_row(row.values())
    print(table)
else:
    # FAILED REQUEST
    print(f'FAILED REQUEST | STATUS: 200 {response.status_code}')

# PEDIR AL USUARIO EL DPID DEL SWITCH
switch_dpid = input("\nIngrese el DPID del switch para ver sus Flow Entries: ").strip()

# CONSULTAR FLOWS DEL SWITCH SELECCIONADO
flows_api = f'wm/core/switch/{switch_dpid}/flow/json'
url_flows = f'http://{controller_ip}:8080/{flows_api}'
response_flows = requests.get(url=url_flows, headers=headers)

if response_flows.status_code == 200:
    print(f'\nFLOW ENTRIES DEL SWITCH {switch_dpid} | STATUS: 200')
    data_flows = response_flows.json()

    # Validar si existen flujos
    if "flows" in data_flows and len(data_flows["flows"]) > 0:
        flows = data_flows["flows"]
        keys = flows[0].keys()
        table = PrettyTable(keys)
        for flow in flows:
            table.add_row(flow.values())
        print(table)
    else:
        print("No se encontraron Flow Entries para este switch.")
else:
    print(f'FAILED REQUEST | STATUS: {response_flows.status_code}')