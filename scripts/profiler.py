import json
import os
import argparse
import sys
import uuid
import pycountry


parser = argparse.ArgumentParser(description="Script to convert MISP STIX ffiles into ATOM STIX files")
parser.add_argument(
        'filename', type=str, nargs='+',
        help='Source MISP STIX file in JSON format')


def load_file(filename):
    data = {}
    if (os.path.isfile(filename)):
        with open(filename, 'r') as f:
            data = json.load(f)
    else:
        return FileNotFoundError
    
    return data


def save_file(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)


def retrieve_entry(search_key, search_value, data):
    collected = []
    for i in range(0, len(data)):
        # Look for entry with specific type
        if search_key in data[i]:
            if data[i][search_key] == search_value:
                collected.append(i)
    
    return collected


def update_keys(search_key, data):
    for entry in data:
        for key in list(entry.keys()):
            if key == search_key:
                del entry[key]

            elif key.startswith('x_misp'):
                entry['x'+ key[6:]] = entry.pop(key)
    
    return data


def grouping_to_report(data):
    # Get indexes of objects that are of type grouping
    # Assumption that only one campaign per event so always expect first index
    [group] = retrieve_entry('type', 'grouping', data)
    [identity] = retrieve_entry('type', 'identity', data)
    sectors = []

    # Change type to report
    data[group]['type'] = "report"
    data[group]['id'] = "report" + data[group]['id'][8:]

    data[identity]['id'] = f'identity--{str(uuid.uuid4())}'
    data[group]['created_by_ref'] = data[identity]['id']
    data[group]['object_refs'].append(data[identity]['id'])

    # Collect list of sectors via tags on MISP
    for tag in data[group]['labels']:
        tag_data = tag.split(': ')
        if len(tag_data) == 2:
            if tag_data[0].lower() == 'sector':
                sectors.append(tag_data[1].lower())
        
    return data, sectors


def collect_attributes(data):
    campaign_data = {}
    countries = []
    [campaign_index] = retrieve_entry('x_name', 'campaign', data)
    attributes = data[campaign_index]['x_attributes']
    for object in attributes:
        campaign_data[object['object_relation'].replace('-', '_')] = object['value']
    
    country_index = retrieve_entry('x_type', 'target-location', data)
    for index in country_index:
        countries.append(pycountry.countries.search_fuzzy(data[index]['x_value'])[0].alpha_2)
    
    del data[campaign_index]

    return campaign_data, {"x_cta_country": countries }


def adjust_actor(data):
    [actor] = retrieve_entry('type', 'threat-actor', data)
    data[actor]['type'] = 'intrusion-set'
    data[actor]['id'] = 'intrusion-set' + data[actor]['id'][12:]

    return data


def adjust_identity(data, labels):
    [identity] = retrieve_entry('type', 'identity', data)
    data[identity].update(labels)

    return data


def campaign_builder(data, campaign_data):
    [baseline] = retrieve_entry('type', 'report', data)
    campaign_entry = {}
    campaign_entry['type'] = 'campaign'
    campaign_entry['id'] = 'campaign--' + str(uuid.uuid4())
    campaign_entry['name'] = data[baseline]['name']
    campaign_entry['created'] = data[baseline]['created']
    campaign_entry['modified'] = data[baseline]['modified']

    campaign_entry.update(campaign_data)

    data.append(campaign_entry)

    #Add to report
    data[baseline]['object_refs'].append(campaign_entry['id'])

    return data, campaign_entry['id']


def attack_pattern_fixer(data):
    intrusion_index = retrieve_entry('type', 'attack-pattern', data)

    for index in intrusion_index:
        [ID] = [label.split('"')[1].split('- ')[1] for label in data[index]['labels'] if label.startswith('misp-galaxy:mitre-attack-pattern')]
        data[index]['name'] = f"{ID}: {data[index]['name']}"

    return data


def report_builder(data):
    [existing_report] = retrieve_entry('type', 'report', data)
    [intrusion] = retrieve_entry('type', 'intrusion-set', data)

    report_entry = {}
    report_entry['type'] = 'report'
    report_entry['id'] = 'report--' + str(uuid.uuid4())
    report_entry['created'] = data[existing_report]['created']
    report_entry['modified'] = data[existing_report]['modified']
    report_entry['name'] = data[intrusion]['name']
    report_entry['description'] = data[intrusion]['description']
    report_entry['object_refs'] = [data[intrusion]['id'], data[existing_report]['id']]
    report_entry['labels'] = ["atom-playbook","intrusion-set"]
    data.append(report_entry)

    return data


def indicator_campaign_relationship(data, id):
    [report] = retrieve_entry('type', 'report', data)
    [identity] = retrieve_entry('type', 'identity', data)
    indicator_index = retrieve_entry('type', 'indicator', data)
    for index in indicator_index:
        relationship = {}
        relationship['type'] = 'relationship'
        relationship['spec_version'] = "2.1"
        relationship['id'] = 'relationship--' + str(uuid.uuid4())
        relationship['relationship_type'] = 'indicates'
        relationship['created'] = data[index]['created']
        relationship['modified'] = data[index]['modified']
        relationship['source_ref'] = data[index]['id']
        relationship['target_ref'] = id

        data[index]['name'] = ", ".join([x['phase_name'] for x in data[index]['kill_chain_phases']])
        data[index]['created_by_ref'] = data[identity]['id']

        data.append(relationship)
        data[report]['object_refs'].append(relationship['id'])
    
    return data


def process_file(original_data):
    # Remove all spec_versions & replace misp keys with standard keys
    custom_data = update_keys("spec_version", original_data)

    # Collect the first_seen, last_seen and country data
    campaign_data, array_labels = collect_attributes(custom_data)

    # Convert grouping to reports & obtain sector information
    custom_data, sectors = grouping_to_report(custom_data)
    array_labels['sectors'] = sectors

    # Adapt threat actor
    custom_data = adjust_actor(custom_data)
 
    # Adjust identity to contain attributes
    custom_data = adjust_identity(custom_data, array_labels)

    # Create campaign
    custom_data, campaign_id = campaign_builder(custom_data, campaign_data)

    # Add TTP ID to entries
    custom_data = attack_pattern_fixer(custom_data)

    # Fix relationships & adddress namings in references if required
    custom_data = indicator_campaign_relationship(custom_data, campaign_id)

    # Generate new top-level report
    custom_data = report_builder(custom_data)

    return custom_data


if __name__ == '__main__':
    args = parser.parse_args()

    complete_file = {
        "type": "bundle",
        "id": f"bundle--{str(uuid.uuid4())}",
        "spec_version": "2.0",
        "objects": []
    }

    output_filename = "-campaign.json"


    for filename in args.filename:
        # Load file from arguments
        original_data = load_file(filename)

        # Process file
        custom_objects = process_file(original_data['objects'])

        # Remove duplicate items under objects that have the same ID
        ids = [x['id'] for x in complete_file['objects']]

        for item in custom_objects:
            if item['id'] not in ids:
                complete_file['objects'].append(item)

    # Check if only one threat actor present
    actors = retrieve_entry('type', 'intrusion-set', complete_file['objects'])
    if len(actors) > 1:
        print("Multiple threat actors detected. Please re-select the appropriate campaigns and ensure only 1 threat actor is present across both.")
        exit()
    else: 
        output_filename = complete_file['objects'][actors[0]]['name'] + output_filename

    # If multiple files have been combined
    # Combine top level report to include all sub-reports
    report_ids = retrieve_entry('type', 'report', complete_file['objects'])
    true_index = -1
    for index in report_ids:
        if 'created_by_ref' not in complete_file['objects'][index]:
            # Correct report found
            if true_index == -1:
                true_index = index
            else:
                [report_id] = [x for x in complete_file['objects'][index]['object_refs'] if x.startswith('report--')]
                complete_file['objects'][true_index]['object_refs'].append(report_id)
                del complete_file['objects'][index]

    save_file(output_filename, complete_file)