import requests

# Chave de API do VirusTotal
API_KEY = "API_HERE"

# Função para consultar um sample no VirusTotal
def consultar_sample(hash):
    url = f"https://www.virustotal.com/vtapi/v2/file/report"
    params = {"apikey": API_KEY, "resource": hash}
    response = requests.get(url, params=params)
    return response.json()
print("""
 ______  ______  ______  ______  ______  __  __  ______  __  __    __  ______ __      ______  __   ________  
/\  ___\/\  ___\/\  __ \/\  == \/\  ___\/\ \_\ \/\  ___\/\ \/\ "-./  \/\  == /\ \    /\  ___\/\ \ / /\__  _\ 
\ \___  \ \  __\\ \  __ \ \  __<\ \ \___\ \  __ \ \___  \ \ \ \ \-./\ \ \  _-\ \ \___\ \  __\\ \ \'/\/_/\ \/ 
 \/\_____\ \_____\ \_\ \_\ \_\ \_\ \_____\ \_\ \_\/\_____\ \_\ \_\ \ \_\ \_\  \ \_____\ \_____\ \__|   \ \_\ 
  \/_____/\/_____/\/_/\/_/\/_/ /_/\/_____/\/_/\/_/\/_____/\/_/\/_/  \/_/\/_/   \/_____/\/_____/\/_/     \/_/ 
                                                                                                             
 by SlackXz
""")
def main():
    hash = input("Digite o hash do sample que deseja consultar: ")

    # Consultar o sample no VirusTotal
    resultado = consultar_sample(hash)

    # Exibir o resultado
    if resultado["response_code"] == 1:
        print("Resultado da consulta:")
        print(f"Detecções totais: {resultado['positives']}/{resultado['total']}")
        print("Detecções individuais:")
        for scanner, resultado_scan in resultado["scans"].items():
            print(f"{scanner}: {resultado_scan['result']}")
    else:
        print("Sample não encontrado ou ainda não analisado.")

if __name__ == "__main__":
    main()