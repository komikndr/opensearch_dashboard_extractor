import argparse
import requests
import json
import warnings
import re

from requests.auth import HTTPBasicAuth
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

def get_index_name_from_index_pattern(saved_objects_api_url, index_pattern_id, auth, headers):
    url = f"{saved_objects_api_url}/index-pattern/{index_pattern_id}"
    response = requests.get(url, auth=auth, headers=headers, verify=False)
    response.raise_for_status()
    
    index_pattern_data = response.json()
    index_name = index_pattern_data['attributes']['title']
    
    return index_name

def get_kibana_saved_object(saved_object_url, auth, headers):
    response = requests.get(saved_object_url, auth=auth, headers=headers, verify=False)
    response.raise_for_status()
    return response.json()

def parse_kibana_saved_object(saved_object):
    search_source_json_str = saved_object['attributes']['kibanaSavedObjectMeta']['searchSourceJSON']
    vis_state_str = saved_object['attributes']['visState']
    search_source_json = json.loads(search_source_json_str)
    vis_state = json.loads(vis_state_str)
    return search_source_json, vis_state

def construct_es_query(search_source_json, vis_state):
    es_aggs = {}
    for agg in vis_state.get('aggs', []):
        if agg['type'] == 'terms':
            es_aggs[agg['id']] = {
                "terms": {
                    "field": agg['params']['field'],
                    "order": {
                        "_count": "desc"
                    },
                    "size": agg['params'].get('size', 5)
                }
            }
    
    es_query = {
        "size": 0,
        "aggs": es_aggs,
        "_source": {"excludes": []},
        "stored_fields": ["*"],
        "script_fields": {},
        "docvalue_fields": [],
        "query": {
            "bool": {
                "must": [],
                "filter": [{"match_all": {}}],
                "should": [],
                "must_not": []
            }
        }
    }
    
    return es_query

def generate_request_body(index_name, search_source_json, vis_state):
    es_query = construct_es_query(search_source_json, vis_state)
    request_body = {
        "params": {
            "index": index_name,
            "body": es_query,
        }
    }
    return request_body

def get_visualization_index_pattern_mapping(saved_objects_api_url, dashboard_url, auth, headers):
    dashboard_id = re.search(r'/view/([\w-]+)', dashboard_url).group(1)
    dashboard_url = f'{saved_objects_api_url}/dashboard/{dashboard_id}'
    dashboard = get_kibana_saved_object(dashboard_url, auth, headers)
    references = dashboard['references']
    
    visualization_index_pattern_mapping = {}
    
    for reference in references:
        if reference['type'] == 'visualization':
            visualization_id = reference['id']
            visualization_url = f'{saved_objects_api_url}/visualization/{visualization_id}'
            visualization_object = get_kibana_saved_object(visualization_url, auth, headers)
            try:
                index_pattern_id = visualization_object['references'][0]['id']
                visualization_index_pattern_mapping[visualization_id] = index_pattern_id
            except:
                pass
    
    return visualization_index_pattern_mapping

def main(args):
    # Define URLs and credentials
    kibana_url_match = re.match(r'(https?://[^/]+)', args.url)
    if kibana_url_match:
        kibana_url = kibana_url_match.group(1)
    else:
        raise ValueError("Invalid URL format: Missing protocol (HTTP/HTTPS)")
    
    saved_objects_api_url = f'{kibana_url}/api/saved_objects'
    auth = HTTPBasicAuth(args.username, args.password)
    headers = {
        'osd-xsrf': 'osd-fetch',
        'Content-Type': 'application/json'
    }
    
    dashboard_url = args.url
    visualization_index_pattern_mapping = get_visualization_index_pattern_mapping(saved_objects_api_url, dashboard_url, auth, headers)
    
    request_bodies = []
    
    for visualization_id, index_pattern_id in visualization_index_pattern_mapping.items():
        vis_url = f'{saved_objects_api_url}/visualization/{visualization_id}'
        vis_object = get_kibana_saved_object(vis_url, auth, headers)
        search_source_json, vis_state = parse_kibana_saved_object(vis_object)
        index_name = get_index_name_from_index_pattern(saved_objects_api_url, index_pattern_id, auth, headers)
        request_body = generate_request_body(index_name, search_source_json, vis_state)
        vis_title = vis_object['attributes']['title']
        request_bodies.append({"title": vis_title, "response_body": request_body})
    
    json_output = json.dumps(request_bodies, indent=2)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(json_output)
    else:
        print(json_output)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract and dump JSON file of Kibana/OpenDashboard")
    parser.add_argument("url", help="Kibana/OpenDashboard URL")
    parser.add_argument("-u", "--username", help="Username")
    parser.add_argument("-p", "--password", help="Password")
    parser.add_argument("-o", "--output", help="Output JSON file")
    
    args = parser.parse_args()
    
    if not (args.username and args.password):
        parser.error("Username and password are required.")

    main(args)
