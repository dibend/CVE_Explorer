import requests
import gradio as gr

# Function to fetch CVE data from CIRCL API
def fetch_cve_data():
    url = 'https://cve.circl.lu/api/last'
    headers = {'User-Agent': 'Mozilla/5.0'}
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        cve_data = response.json()
        
        cve_list = []
        for entry in cve_data:
            assigner = entry.get('assigner', 'N/A')
            capec_list = entry.get('capec', [])
            
            for capec in capec_list:
                cve_list.append({
                    'CVE ID': entry.get('id', 'N/A'),
                    'CAPEC ID': capec.get('id', 'N/A'),
                    'CAPEC Name': capec.get('name', 'N/A'),
                    'Summary': capec.get('summary', 'N/A'),
                    'Prerequisites': capec.get('prerequisites', 'N/A'),
                    'Related Weaknesses': ', '.join(capec.get('related_weakness', [])),
                    'Solutions': capec.get('solutions', 'N/A'),
                    'Assigner': assigner
                })
        
        return cve_list
    
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return []

# Gradio interface
def gradio_app():
    cve_data = fetch_cve_data()

    with gr.Blocks() as demo:
        for entry in cve_data:
            cve_id = entry['CVE ID']
            capec_id = entry['CAPEC ID']
            capec_name = entry['CAPEC Name']
            summary = entry['Summary']
            prerequisites = entry['Prerequisites']
            solutions = entry['Solutions']
            assigner = entry['Assigner']

            # Display all information directly, no buttons
            gr.Markdown(f"### {cve_id}: {capec_name}")
            
            # Auto-populate the fields with respective information
            gr.Textbox(value=summary, label="Summary", interactive=False)
            gr.Textbox(value=prerequisites, label="Prerequisites", interactive=False)
            gr.Textbox(value=solutions, label="Solutions", interactive=False)
            gr.Textbox(value=assigner, label="Assigner", interactive=False)

            gr.Markdown("---")  # Separator for each entry

    return demo

# Launch the Gradio app
gradio_app().launch(share=True, debug=True)
