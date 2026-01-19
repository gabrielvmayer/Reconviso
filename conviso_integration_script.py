#!/usr/bin/env python3
import json
import os
import sys
import requests

class ConvisoPlatform:
    def __init__(self, api_key, company_id=None):
        self.api_url = "https://api.convisoappsec.com/graphql"
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "x-api-key": api_key,
            "Content-Type": "application/json"
        }
        # Adiciona o contexto da empresa se fornecido
        if company_id:
            self.headers["x-company-id"] = company_id

    def query(self, query, variables=None):
        try:
            response = requests.post(self.api_url, json={'query': query, 'variables': variables}, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"❌ Erro de conexão GraphQL: {e}")
            if 'response' in locals():
                print(f"Detalhes: {response.text}")
            return {}

    def create_vulnerability(self, project_id, asset_id, finding):
        mutation = """
        mutation CreateVulnerability($input: CreateVulnerabilityInput!) {
          createVulnerability(input: $input) {
            vulnerability { id title severity }
            errors
          }
        }
        """
        
        sev_map = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
        severity = sev_map.get(finding.get('severity', 'low').lower(), "LOW")

        desc = f"""
        **Ferramenta:** {finding.get('source', 'Nuclei')}
        **Template:** {finding.get('template_id')}
        **URL:** {finding.get('matched_at')}
        
        ### Descrição Técnica
        {finding.get('description')}
        """

        variables = {
            "input": {
                "projectId": project_id,
                "assetId": asset_id,
                "title": finding.get('name')[:250],
                "severity": severity,
                "description": desc,
                "vulnerabilityType": "INFRASTRUCTURE", 
                "status": "IDENTIFIED"
            }
        }

        print(f"⚡ Criando vuln no Projeto {project_id} (Asset {asset_id})...")
        res = self.query(mutation, variables)
        
        data = res.get('data', {})
        if data and data.get('createVulnerability', {}).get('vulnerability'):
            print(f"✅ Vuln criada: {finding.get('name')}")
        else:
            errors = data.get('createVulnerability', {}).get('errors')
            print(f"⚠️ Falha ao criar vuln: {errors}")

    def upload_report_as_evidence(self, project_id, report_path):
        if not os.path.exists(report_path):
            print("⚠️ Relatório de IA não encontrado para upload.")
            return

        with open(report_path, 'r') as f:
            content = f.read()

        mutation = """
        mutation CreateNote($input: CreateNoteInput!) {
          createNote(input: $input) {
            note { id }
            errors
          }
        }
        """
        
        variables = {
            "input": {
                "projectId": project_id,
                "title": "🤖 Evidência de Reconhecimento (IA)",
                "content": content,
                "scope": "PROJECT"
            }
        }

        print("📤 Enviando relatório de IA para o projeto...")
        res = self.query(mutation, variables)
        
        data = res.get('data', {})
        if data and data.get('createNote', {}).get('note'):
            print("✅ Relatório anexado ao projeto com sucesso!")
        else:
            print(f"❌ Erro ao anexar relatório: {res}")

def main():
    # Verifica argumentos: script + json + project + asset + company
    if len(sys.argv) < 5:
        print("Uso: python conviso_integration.py <json_file> <project_id> <asset_id> <company_id>")
        sys.exit(1)

    findings_file = sys.argv[1]
    project_id = sys.argv[2]
    asset_id = sys.argv[3]
    company_id = sys.argv[4]  # Recebe o Company ID
    
    report_file = "AI_RECON_REPORT.md"

    print(f"🚀 Iniciando Integração Conviso")
    print(f"📍 Contexto: Company {company_id} | Project {project_id} | Asset {asset_id}")
    
    client = ConvisoPlatform(os.environ.get('CONVISO_API_KEY'), company_id)

    # 1. Processar Findings
    if os.path.exists(findings_file):
        try:
            with open(findings_file) as f:
                data = json.load(f)
                
            findings = data.get('findings', [])
            print(f"🔍 Total de findings para analisar: {len(findings)}")

            for finding in findings:
                if finding.get('severity') in ['critical', 'high', 'medium']:
                    client.create_vulnerability(project_id, asset_id, finding)
                    
        except Exception as e:
            print(f"❌ Erro ao processar findings: {e}")
    else:
        print(f"⚠️ Arquivo {findings_file} não encontrado.")

    # 2. Upload do Relatório IA
    client.upload_report_as_evidence(project_id, report_file)

if __name__ == "__main__":
    main()
