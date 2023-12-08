# AWS_resource_check

AWS_resource_checkは、AWS CloudTrailのログから特定のユーザーによるEC2およびRDSのイベントを取得し、分析して結果を表示するスクリプトです。このツールは、AWSのリソース使用状況を監視し、セキュリティやリソース管理のための洞察を提供します。

##　対応サービス
EC2instance、RDS


### 必要条件
- AWS CLIでcloudtrailイベント履歴に対するアクセス権限があるユーザを使用していること


### インストール手順
1. このリポジトリをクローンまたはダウンロードします。
2. 必要に応じて、スクリプトに実行権限を与えます。例: `chmod +x aws_resource_check.sh`

## 使い方のサマリー

スクリプトはコマンドラインから実行します。次の形式でコマンドを使用してください:

```bash
./aws_resource_check.sh [分数] [ユーザ名]
```
ここで、[分数]は分析対象の時間範囲（分単位）、[ユーザ名]はAWSユーザ名です。

例
```bash
./aws_resource_check.sh 30 testuser
```