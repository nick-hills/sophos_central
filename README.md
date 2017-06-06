# Sophos Central App for Splunk
This Splunk App leverages the Sophos Central API to collect events and alert notifications from registered endpoints and devices.

The application provides an overview dashboard, and fields conforming to CIM 4.8 Malware_*

You will need to obtain an API key from your Sophos Central account. On first run the setup screen will prompt you to configure the app with your account details
 
*Icon made by Freepik from www.flaticon.com*

## Configure the Application
You will need to obtain a Sophos Central API token to start reciving events from Sophos Central. To do so, login to your Sophos Central acocunt, and navigate to Global Settings, and then choose "API Token Management"

![alt text](https://github.com/nickhills81/sophos_central/blob/master/readme_content/Sophos_Central01.png?raw=true)

Choose "New Token" and then provide a name for the token.

![alt text](https://github.com/nickhills81/sophos_central/blob/master/readme_content/Sophos_Central02.png?raw=true)

From the resulting credentials you will need to make note of the endpoint address, api token and authorisation string.
