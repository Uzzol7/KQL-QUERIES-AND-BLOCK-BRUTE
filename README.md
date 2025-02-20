# KQL-QUERIES-AND-BLOCK-BRUTE
KQL queries perfomed in our application, Hydra Commands, 

HYDRA COMMAND FOR BRUTE FORCE 
1.sudo apt install hydra
2.hydra -l Administrator -P passwords.txt rdp://<135.236.210.124>
3. sudo apt install ncrack
4. ncrack -u Administrator -P passwords.txt <135.236.210.124>>:3389




KQL QUERIES

ATTACKS OVER TIME
SecurityAlert | where ProviderName == 'ASI Scheduled Alerts' or ProviderName == 'CustomAlertRule'

SecurityEvent
| where EventID ==4625
| project  TimeGenerated,EventID, WorkstationName, Computer,Account, LogonType, IpAddress
| extend  AccountEntity = Account
| extend IPEntitiy =IpAddress

Chart
SecurityEvent
| where EventID == 4625
| where LogonType == 3
| summarize FailedAttempts=count() by bin(TimeGenerated, 10m)
| render timechart





////BLOCK-IP code

{
    "definition": {
        "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
        "contentVersion": "1.0.0.0",
        "triggers": {
            "Microsoft_Sentinel_alert": {
                "type": "ApiConnectionWebhook",
                "inputs": {
                    "host": {
                        "connection": {
                            "name": "@parameters('$connections')['azuresentinel']['connectionId']"
                        }
                    },
                    "body": {
                        "callback_url": "@{listCallbackUrl()}"
                    },
                    "path": "/subscribe"
                }
            }
        },
        "actions": {
            "Parse_JSON": {
                "runAfter": {},
                "type": "ParseJson",
                "inputs": {
                    "content": "@triggerBody()?['AlertDisplayName']",
                    "schema": {
                        "properties": {
                            "AttackerIP": {
                                "type": "string"
                            }
                        }
                    }
                }
            }
        },
        "outputs": {},
        "parameters": {
            "$connections": {
                "type": "Object",
                "defaultValue": {}
            }
        }
    },
    {
    "name": "Block-Attacker-IP",
    "actions": [
        {
            "type": "IP Block",
            "target": "AzureFirewall",
            "ip": "{Attacker_IP}"
        }
    ]
},
    "parameters": {
        "$connections": {
            "type": "Object",
            "value": {
                "azuresentinel": {
                    "id": "/subscriptions/fdd6601d-5019-4904-9a1d-edb1dc8fd062/providers/Microsoft.Web/locations/northeurope/managedApis/azuresentinel",
                    "connectionId": "/subscriptions/fdd6601d-5019-4904-9a1d-edb1dc8fd062/resourceGroups/newvmexp_group/providers/Microsoft.Web/connections/azuresentinel",
                    "connectionName": "azuresentinel"
                }
            }
        }
    }
}
