#!/bin/bash

# 分数とユーザ名を指定（例：60分前、ユーザ名）
MINUTES_AGO=$1
USERNAME=$2

# 現在時刻と開始時刻を算出（ISO 8601フォーマット）
END_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
START_TIME=$(date -u -d "$MINUTES_AGO minutes ago" +"%Y-%m-%dT%H:%M:%SZ")
RESOURCE_NAME="ec2.amazonaws.com"
# CloudTrailのイベント履歴をJSONファイルに保存（ユーザ名でフィルター）
JSON_FILE="cloudtrail_ec2_events.json"
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=$USERNAME \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=$RESOURCE_NAME \
  --start-time "$START_TIME" \
  --end-time "$END_TIME" > $JSON_FILE

RESOURCE_NAME="rds.amazonaws.com"
JSON_FILE="cloudtrail_rds_events.json"
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=$USERNAME \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=$RESOURCE_NAME \
  --start-time "$START_TIME" \
  --end-time "$END_TIME" > $JSON_FILE
# Pythonスクリプトのファイル名を定義
PYTHON_SCRIPT="display_json.py"

# Pythonスクリプトを作成
cat << EOF > $PYTHON_SCRIPT
# -*- coding: utf-8 -*-
import json

def load_cloudtrail_data(file_path):
    """
    指定されたファイルパスからJSONデータを読み込み、Pythonの辞書として返す関数。
    JSONの読み込みに失敗した場合はNoneを返す。
    """
    try:
        with open(file_path, 'r', newline=None) as file:
            return json.load(file)
    except Exception as e:
        print(f"Error loading JSON file: {e}")
        return None

def filter_events_by_event_names(data, event_name_groups):
    """
    イベント名に基づいてCloudTrailログデータをフィルタリングする関数。
    data: CloudTrailのログデータ。
    event_name_groups: イベント名のグループを含む辞書。
    各グループ名に対して、指定されたイベント名を含むイベントのリストを返す。
    """
    if data is None:
        return {}

    filtered_events = {}
    for group_name, event_names in event_name_groups.items():
        filtered_events[group_name] = [
            event for event in data.get('Events', []) 
            if event['EventName'] in event_names
        ]
    return filtered_events

def extract_specified_items(event_data, keys_to_extract):
    """
    指定されたキーのパスに基づいてイベントデータから特定の項目を抽出する関数。
    event_data: イベントデータ。
    keys_to_extract: 抽出するキーのパスのリスト。
    指定されたキーパスに従ってデータを抽出し、辞書形式で返す。
    """
    extracted_data = {}

    def extract(data, key_path):
        if not key_path:
            return data

        current_key = key_path[0]
        next_data = data.get(current_key, '不明')

        if isinstance(next_data, list):
            return [extract(item, key_path[1:]) for item in next_data]
        elif isinstance(next_data, dict):
            return extract(next_data, key_path[1:])
        else:
            return next_data

    for key in keys_to_extract:
        key_path = key.split('.')
        extracted_data[key] = extract(event_data, key_path)

    return extracted_data

def remove_duplicates_from_first_list(first_list, second_list, key):
    """
    二つのリストを比較し、一つ目のリストから二つ目のリストに存在する要素を除去する関数。
    first_list, second_list: 比較するリスト。
    key: 重複を判定するためのキー。
    一つ目のリストから重複を除去した新しいリストを返す。
    """
    second_list_ids = set()
    for event in second_list:
        extracted_items = extract_specified_items(event, [key])[key]
        if isinstance(extracted_items, list):
            second_list_ids.update(extracted_items)
        else:
            second_list_ids.add(extracted_items)

    unique_first_list = []
    for event in first_list:
        extracted_items = extract_specified_items(event, [key])[key]
        if isinstance(extracted_items, list):
            if not any(item in second_list_ids for item in extracted_items):
                unique_first_list.append(event)
        elif extracted_items not in second_list_ids:
            unique_first_list.append(event)

    return unique_first_list

def analyze_events(file_path,Create_Event_Name,Delete_Event_Name,Check_prm):
    """
    指定されたCloudTrailログファイルから特定のイベントに関連するデータを解析し、結果を返す関数。

    Args:
        file_path (str): CloudTrailのログファイルへのパス。
        Create_Event_Name (str): 作成イベント（例:EC2インスタンスの起動）の名前。
        Delete_Event_Name (str): 削除イベント（例:EC2インスタンスの終了）の名前。
        Check_prm (str): 重複をチェックするためのパラメータ（例：リソース名）。

    Returns:
        list: 指定された作成イベントに関連するデータを含む辞書のリスト。削除イベントで既に削除されたリソースは除外される。
    """
    data = load_cloudtrail_data(file_path)
    event_name_groups = {
        'Create': [Create_Event_Name],
        'Delete': [Delete_Event_Name]
    }

    filtered_data = filter_events_by_event_names(data, event_name_groups)
    created_instances = filtered_data.get('Create', [])
    deleted_instances = filtered_data.get('Delete', [])
    unique_created_instances = remove_duplicates_from_first_list(
        created_instances, deleted_instances, 
        Check_prm
    )
    
    results = []
    for event in unique_created_instances:
        extracted_data = extract_specified_items(event, [
            'CloudTrailEvent'
        ])
        results.append(extracted_data)

    return results

def extract_value_from_json(data, key_path):
    """
    指定されたキーパスに従ってJSONデータから値を抽出する関数。
    data: JSONデータを表す辞書。
    key_path: 抽出する値のキーパス。
    キーパスに従って値を抽出し、見つかった値を返す。
    """
    current_data = data
    for key in key_path.split('.'):
        if key in current_data:
            current_data = current_data[key]
        else:
            return None
    return current_data

if __name__ == "__main__":
    file_path = 'cloudtrail_ec2_events.json'
    print("----------------EC2instance----------------")
    results = analyze_events(file_path,'RunInstances','TerminateInstances','Resources.ResourceName')
    if results:
        for result in results:
            resources = result.get('CloudTrailEvent', [])
            region = extract_value_from_json(json.loads(resources),'awsRegion')
            itmes = extract_value_from_json(json.loads(resources),'responseElements.instancesSet.items')
            instance_id = next((item['instanceId'] for item in itmes if 'instanceId' in item), None)
            instanceType = next((item['instanceType'] for item in itmes if 'instanceType' in item), None)
            print("Instance ID:", instance_id ,"Instance Type:", instanceType)
            print("URL : https://"+ region +".console.aws.amazon.com/ec2/home?region="+ region +"#InstanceDetails:instanceId="+ instance_id)
    else:
        print("結果はありません。")
    
    file_path = 'cloudtrail_rds_events.json'
    print("----------------RDScluster----------------")
    results = analyze_events(file_path,'CreateDBInstance','DeleteDBInstance','Resources.ResourceName')
    if results:
        for result in results:
            resources = result.get('CloudTrailEvent', [])
            region = extract_value_from_json(json.loads(resources),'awsRegion')
            instance_id = extract_value_from_json(json.loads(resources),'responseElements.dBInstanceIdentifier')
            instanceType = extract_value_from_json(json.loads(resources),'requestParameters.dBInstanceClass')
            print("Instance ID:", instance_id ,"Instance Type:", instanceType)
            print("URL : https://"+ region +".console.aws.amazon.com/rds/home?region="+ region +"#InstanceDetails:instanceId="+ instance_id+";is-cluster=false")
    else:
        print("結果はありません。")
EOF

# Pythonスクリプトを実行
python3 $PYTHON_SCRIPT
