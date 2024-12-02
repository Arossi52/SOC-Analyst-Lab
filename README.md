# SOC-Analyst-Lab

## Objective

The SOC Analyst Lab project aimed to establish a controlled environment for generating custom alerts and performing responsive actions to those alerts. The primary focus was to create rules in Wazuh that would trigger alerts, send the information to Shuffle for automated responsive actions, OSINT for enrichment, and TheHive to generate alerts in case management, simulating an automated SOC environment. This hands-on experience was designed to deepen understanding of SOAR implementation as well as the processes to create custom configurations that would alert for potentially malicious events.

### Skills Learned

- Advanced understanding of Wazuh and SOAR implementation with shuffle.
- Proficiency in analyzing and interpreting network logs.
- Ability to generate and recognize attack signatures and patterns.
- Enhanced knowledge of network protocols and security vulnerabilities.
- Development of critical thinking and problem-solving skills in cybersecurity.

### Tools Used


- Wazuh for log ingestion, XDR and SIEM capabilities.
- TheHive for case management.
- Telemetry generation with Mimikatz.
- Shuffle for SOAR automation
- Digital Ocean cloud service for the deployment of hosts.

## Steps

 First I started by using Draw.io to create a diagram of my lab.
![SOC automation lab drawio](https://github.com/user-attachments/assets/f0b693f7-1482-45f6-a0d3-bc9f389c713a)


 We start by using the cloud service Digital Ocean to create a Ubuntu server that will act as our Wazuh Manager. I selected a Ubuntu 22.04 machine with 8gb of ram.
 ![Screenshot 2024-11-05 144118](https://github.com/user-attachments/assets/d2beaa28-0b8e-4865-85fa-b4195c7d893e)

I then created a Firewall on Digital Ocean that will accept all inbound TCP and UDP traffic only from my computer's public IP as well as all inbound traffic on port 9000 (this will be used for TheHive server) and assign it to the server I just created.
![firewall 1](https://github.com/user-attachments/assets/b8b5d4cc-b429-4864-b290-c62f0f1581dd)

 I SSH into the newly spun up machine using Powershell and performed updates and upgrades using the command `apt-get update && apt-get upgrade`. After that completed, I installed the Wazuh Manager using `curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a`. After the installation is completed, be sure to take note of the username and password given to access the Wazuh Dashboard. - If you forget to take note of it, you can find it in the `wazuh-passwords.txt` file in the `~/wazuh-install-files` directory 
 ![Screenshot 2024-11-05 150531](https://github.com/user-attachments/assets/a9a95dd2-4078-49db-8656-aaf5438d6c57)

We can connect to our Wazuh Dashboard by going to https://xxx.xx.x.xx where the x's will be replaced by our Wazuh Server's public IP given from Digital Ocean. After arriving at the login page, use the credentials retrieved in the previous step to log in to the manager:
![Screenshot 2024-11-05 152829](https://github.com/user-attachments/assets/07719bb4-6910-497f-a6c4-808f7248803f)


# The Hive Server
Next we will create a new Ubuntu machine for TheHive server using the same steps we used for the first machine. We will also assign the same firewall we created for the Wazuh Manager to this new machine and then SSH into it. After performing the update and upgrade, I began installing the dependencies and the 4 components that are needed for TheHive to work: Java, Cassandra, Elasticsearch, and TheHive itself. 

### **Dependencies**
`apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl  software-properties-common python3-pip lsb-release`

### **Install Java**
`wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor  -o /usr/share/keyrings/corretto.gpg`
`echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" |  sudo tee -a /etc/apt/sources.list.d/corretto.sources.list`
`sudo apt update`
`sudo apt install java-common java-11-amazon-corretto-jdk`
`echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment` 
`export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"`
![Screenshot 2024-11-05 152817](https://github.com/user-attachments/assets/0f7206a3-32e3-438f-923f-dd1c21c046b0)

### **Install Cassandra**
`wget -qO -  https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor  -o /usr/share/keyrings/cassandra-archive.gpg`
`echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" |  sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list`
`sudo apt update`
`sudo apt install cassandra`
![Cassandra](https://github.com/user-attachments/assets/d53c7b25-3a12-4f3f-947b-abfa09dd8aa7)

-I modified the Cassandra configuration file using `nano /etc/cassandra/cassandra.yaml` and changed the cluster name to my name `Arossi52` and changed the `listen_address` and `rpc_address` from `local_host` to the public IP of my TheHive server. The last change made was the seed address from the default local host address `127.0.0.1:7000` to the IP of my TheHive machine on port 7000. Save out the file and close.
- Then you must stop Cassandra using `systemctl stop cassandra.service`
- Use `rm -rf /var/lib/cassandra/*` to delete any files that were created with the old configuration
- Restart the service using `systemctl start cassandra.service` and double check that its running by typing `systemctl status cassandra.service` 
![cassandrayaml1](https://github.com/user-attachments/assets/b3a7db07-2df4-4523-91c7-ed4dd8ef1ea7)
![cassandrayaml2](https://github.com/user-attachments/assets/dda9514b-d9f9-48a1-aa43-d7951b6b58aa)
![cassandrayaml3](https://github.com/user-attachments/assets/88f15b39-9a1e-48b2-9991-f1675e283453)
![cassandrayaml4](https://github.com/user-attachments/assets/60cbb0ff-d405-4bac-b0ee-26d800ed3f81)


### **Install ElasticSearch**
`wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch |  sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg`
`sudo apt-get install apt-transport-https`
`echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" |  sudo tee /etc/apt/sources.list.d/elastic-7.x.list`
`sudo apt update`
`sudo apt install elasticsearch`
![elasticsearch](https://github.com/user-attachments/assets/620ea156-d5df-4b75-ae2e-ca1adf8153a0)

-Modify the Elasticsearch configuration file using `nano /etc/elasticsearch/elasticsearch.yml`
- uncomment out `cluster.name` (delete the # in front) and change it from `my-application` to `thehive`
- uncomment `node.name` and continue
- uncomment `network.host` and change the address to the public ip of thehive server
- uncomment `http.port`
- uncomment `cluster.initial_master_nodes` and remove `"node-2"` as we are only using 1 node
- start and enable Elasticsearch using `systemctl start elasticsearch` and `systemctl enable elasticsearch` and then verify it is running with `systemctl status elasticsearch`
###### ***OPTIONAL ELASTICSEARCH***
Create a jvm.options file under /etc/elasticsearch/jvm.options.d and put the following configurations in that file.
`-Dlog4j2.formatMsgNoLookups=true`
`-Xms2g`
`-Xmx2g`
This tells Elasticsearch to allocate only 2 GBs of memory to Java to ensure we have no crashes. (you can alter this allocation this by changing the 2s in both -Xms2g and -Xmx2g)
![jvm options](https://github.com/user-attachments/assets/bd69a7e7-d305-4b30-a305-d14ef7c055cb)


### **Install TheHive**
`wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg`
`echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list`
`sudo apt-get update`
`sudo apt-get install -y thehive`

After installing all components, I checked the file path that thehive user on the ubuntu machine will need access to using `ls -la /opt/thp` and modified ownership of the filepath using `chown -R thehive:thehive /opt/thp`. Then I ran the previous command `ls -la /opt/thp` again to ensure thehive had ownership.
![thehive chown](https://github.com/user-attachments/assets/4a7358a5-a981-4d8a-9b59-9087755fb53d)

- We then need to modify TheHive's configuration file using `nano /etc/thehive/application.conf` and changed the `hostname` to TheHive machine's public ip and changed the `cluster-name` to the cluster name we used in our Cassandra configuration file, which in my case was Arossi52. 
- Right below this section you will see `index.search` and below that `hostname` again which we will need to change to Thehive's public ip.
- Scrolling down a little further you will find `# Service configuration` and will need to change the `application.baseURL` from the default and replace `"localhost"` again with your public ip of TheHive and leave it on port 9000.
  ![thehive conf](https://github.com/user-attachments/assets/cd2a739f-e1eb-4cde-a864-aaf3d42b6389)

After setting up all of the configurations it is a good idea to check the status of all 3 services using `systemctl status [servicename].service` to ensure they are all running before continuing. If there is an issue with TheHive always ensure that all 3 services are running as some may stop on their on.

Then type the public ip of TheHive on port 9000 in your internet browser and use the default credentials to sign in. If you get an error, check again to ensure all 3 services are running.
![thehivelogin](https://github.com/user-attachments/assets/d873ddab-a0ad-4754-85da-8c78a5c7bbaa)

### **Wazuh Agent on Windows**
Now I will set up a Windows 10 machine and install sysmon to send logs to Wazuh. This machine doesn't need crazy specs, I spun it up using 4GB of ram. then We will head over to the Wazuh Manager and click the Wazuh. button drop down and click agents. From here, click Deploy new agent. Use your Wazuh public ip for your server address and assign your agent name - mine was Arossi52. Copy the command in step 4 and paste it in Powershell to install the Wazuh agent on your windows machine. You can then start the service by typing `net start wazuhsvc`. 
![Wazuh agent](https://github.com/user-attachments/assets/4e97e1f0-df6c-4ba1-8e24-555fa6134987)

In order to send the telemetry we want to our Wazuh Manager, we will have to install sysmon on our windows machine which we can follow the steps from Microsoft at https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon to do so and refer to this page for Event IDs. Once Sysmon is installed and running, open up event viewer and expand applications and services logs -> Microsoft -> Windows -> Sysmons and right click Operational and select properties.
![Sysmon operational ](https://github.com/user-attachments/assets/aa85b75a-a946-471d-b1fd-b5d3f7532bd3)

Copy the Full Name field and head to C:\Program Files (x86)\ossec-agent and locate the ossec.conf file. Create a new `<localfile>` entry using the copied Full Name field (see screenshot below). I removed everything other than the Sysmon and Active-response sections as I will not be utilizing logs from other services for this project. Save out the file and restart the Wazuh service. (Open Services and right click Sysmon and select restart)

**Note: It's a good idea to create a backup copy of the ossec.conf file prior to doing so.** 
![ossec conf](https://github.com/user-attachments/assets/1d471512-25ed-451c-be85-d3ae8d0970a1)

Now head to the Wazuh Manager dashboard home and click security events and then Events at the top of the page. Search sysmon in the search bar - it may take a few minutes for the Windows machine to generate telemetry. 

### Installing Mimikatz on our Windows Machine
Mimikatz is a well-known application that attackers and Red-teamers use to extract credentials from a machine so system and browser security will flag it as Malicious so we will have to bypass browser and Windows Defender security in order to download and utilize it. We are simply running Mimikatz to generate telemetry and alerts in Wazuh and TheHive. 

- Head to the github for Mimikatz at https://github.com/gentilkiwi/mimikatz/releases/tag/2.2.0-20220919. 

- Download the .zip file - your browser may block the download which you can disable by going into your browser settings and disabling browser security - every browser will differ. 

- You then need to exclude the downloads folder in Windows Defender in order to run . Open Defender -> Virus and Threat Protection -> Manage Settings -> Add or remove exclusions and add the path to your downloads folder.

- Once downloaded, extract all files from the folder and run the mimikatz.exe file in the x64 folder.
![Defender](https://github.com/user-attachments/assets/60cdeaf6-adab-4af7-a6ac-4e8dfa4bd50c)


Head to the Wazuh manager machine and edit the ossec.conf file under `/var/ossec/etc/ossec.conf` as seen below. Restart the Wazuh manager using `systemctl restart Wazuh-manager.service` 
![Screenshot 2024-11-07 151114](https://github.com/user-attachments/assets/1a8ebbe4-376e-41d8-a62f-2ba33ea9f85f)

Now we need to edit the filebeat.yml file so that Wazuh will ingest the logs that are being created.
`nano /etc/filebeat/filebeat.yml` and change `archives: enabled:` to `true` and save out the file. 

Restart Filebeat `systemctl restart filebeat` 
![Screenshot 2024-11-07 150150](https://github.com/user-attachments/assets/0cbaced0-a7f6-4d42-85a9-327a57898019)

Create a new index pattern in Wazuh: Click on the "hamburger" icon on the top left of the screen and click Stack Management
![Screenshot 2024-11-26 173757](https://github.com/user-attachments/assets/89e327ec-d67f-449f-873f-a66424861bef)

Then click Index Patterns and click Create index pattern.
![Screenshot 2024-11-26 173930](https://github.com/user-attachments/assets/a88071f0-ab0f-45b7-b768-776b2e5bc4b5)

For this new index we named it `wazuh-archives-*`. With the * telling it to index everything.
![Screenshot 2024-11-26 173945](https://github.com/user-attachments/assets/8a5f49b9-22e4-4698-b5d2-19b229aaf9bd)

On the next screen select timestamp for the primary time field and finish by clicking create index pattern.
![Screenshot 2024-11-26 174013](https://github.com/user-attachments/assets/126d7fdc-d8eb-4cb2-9798-6d3ea9b7433c)

To check that mimikatz activity is being archived go to the Wazuh manager and under `/var/ossec/logs/archives` run `cat archives.json | grep -i mimkatz` . If mimikatz is running on your windows machine, the result should look something like below. If not, then run the mimkatz.exe file again and repeat the previous step.
![Screenshot 2024-11-07 161749](https://github.com/user-attachments/assets/4602c5d7-cfb7-45e6-b94e-174a50426398)

Next we need to create a rule in Wazuh to trigger when Mimikatz is ran. 
![[Wazuh rules 1.png]]
After clicking on the rules, click manage rule files and then we can search for sysmon to get a guideline of how the rules should look. We want to look at the `0800-sysmon_id_1.xml` because we are interested in sysmon event id 1 which is process creation.
![sysmon rules](https://github.com/user-attachments/assets/a22024b3-f494-4c38-a5d4-4e71721faf79)

Copy one of the rules to use as a template for our Mimikatz rule.
![sysmonid1](https://github.com/user-attachments/assets/9094b9c9-af25-4f2c-88ba-8a9ad9d9937d)

Then go back to the manage rules page and search for `local_rules.xml`
![local rules 2](https://github.com/user-attachments/assets/05b0eb43-4bea-4ea7-b56f-480c75ddb48b)

We will paste in our copied rule and make the changes as seen below. Ensure that the indentation for certain fields is the same as the rule that we copied over. 

**rule ID** - 100002 as all other rule ids are used
**level** - I set to 15 as this is the highest severity level - you can set to your needs accordingly
**field name** - `win.eventdata.originalFileName` this looks for the original name of the file in cases where mimikatz is renamed. This is CASE SENSITIVE otherwise the rule will not trigger
**type** - set to pcre2 which is Regex "regular expression" (?i) ignores case sensitivity for the field VALUE which in our case is `mimikatz\.exe`
**options** - remove this entirely as it is set to no_full_log but we want the entire log
**description** - set this to what you want your rule to say when triggered
**mitre id**** - set to T1003 which is for credential dumping which mimikatz is known to do

Save the file and restart the manager.
![Wazuh custom rule - case sensitive](https://github.com/user-attachments/assets/2371a636-7832-4eab-b7bf-79c40beac487)

As a proof of concept - I went and changed my mimikatz.exe file on my windows machine to pwned.exe to ensure that my rule still triggered even when the application is renamed.

Then, we can go to our Wazuh dashboard we should get a security alert which looks something like this:
![wazuh mimikatz](https://github.com/user-attachments/assets/a5f22a9d-2d21-474e-9204-fdfa4a63d563)

### Using Shuffler for SOAR Automation
Shuffle is an automation tool that I am going to be using to automate responses to specific alerts triggered in Wazuh. You will need to sign up for a free account to get started. Click on Workflows 

Click on Workflows at the top left and then click New Workflow. Name your workflow and give it a use case. What you put here will not make a difference to your workflow but use tags that make sense for what you are doing.
![Shuffler getting started](https://github.com/user-attachments/assets/f2a5740f-a98c-4fd8-8aa7-a39d16aeee95)

Once the workflow is created, start by adding a Webhook application by clicking Triggers on the bottom left of the screen and dragging it from the list onto the workflow. Select it and rename it. 

(You may need to click the blue dot on the top of the webhook icon and drag the arrow over to the "change me" icon to connect the two.)

Copy the webhook URI as this will be needed to integrate with Wazuh.

click Start to start the webhook
![Shuffle Webhook](https://github.com/user-attachments/assets/8178feb6-1f42-4c1a-b966-8829353afb4c)

On our Wazuh manager, `nano /var/ossec/etc/ossec.conf` and add an integration tag in the file. the standard format is:
`<integration>`
  `<name>shuffle</name>`
  `<hook_url>http://IP:3001/api/v1/hooks/HOOK_ID </hook_url> <!-- Replace with your Shuffle hook URL -->`
  `<level>3</level>`
  `<alert_format>json</alert_format>`
  `<options>{"data": {"title": "Custom title"}}</options> <!-- Replace with your custom JSON object -->`
`</integration>`

I removed the options line as I did not need it and pasted in my webhook url. See below for reference:

![Wazuh Shuffle intergration](https://github.com/user-attachments/assets/c1b7ab29-a8e3-447d-83c1-d650a2b1f9db)

I replced the level line with rule_id so that the webhook will receive the logs from Wazuh when the rule we created is triggered.

Be sure to remove the `http://` . I left it in by mistake and had to troubleshoot why my webhook wasn't triggering. Attention to detail is KEY. Save the file and Restart the Wazuh Manager.
![Wazuh Shuffle intergration 2](https://github.com/user-attachments/assets/179c9769-ee0f-473b-a448-af9ee6e78e5d)

I re-ran my mimikatz file on my windows machine to create an alert in Wazuh to trigger my Webhook. 

Click on the running man icon in Shuffle to see workflows that have ran. It may take a minute for it to trigger - refresh your runs until you see it.
![Shuffle execution argument](https://github.com/user-attachments/assets/8c0b14eb-be4d-4ffe-9815-e022acf69bcc)

Next I expanded the eventdata from my Webhook execution and copied the hashes. I then used ChatGPT to create a regex to parse out the SHA256 from this line. This is extracting JUST the SHA256 hash and not the others from the Webhook results.

![ChatGPT regex](https://github.com/user-attachments/assets/ccbf33b0-c479-4279-b6ef-c1fb1798a5df)

copy the result : `SHA256=([A-Fa-f0-9]{64})` and head to your "change me" icon in shuffle. 

- Rename the icon to SHA256_Regex and select Regex capture group in the Find Actions drop down.
- Under input data click the + button and you should be able to look through the fields that were supplied in the previous execution. Select `hashes` under `eventdata`
- Paste the regex that ChatGPT gave in the last box.
- Go back to the show executions tab and click on your execution. Click the rerun workflows button. 
- You can expand the SHA256 Regex and see the SHA256 hash is now displayed under `group_0`
![Shuffle updated regex results](https://github.com/user-attachments/assets/9a51f0ad-b392-4608-9678-121a129dbd02)

## Virustotal Enrichment

Next, we want to use Virustotal to scan the SHA256 hash to see if it is malicious or not. 

Go to virustotal.com and sign up for an account to botain an API key that will be needed for our Workflow. Copy the API key.
![Virustotal API key](https://github.com/user-attachments/assets/10414bbe-511c-4ef3-a110-ab0ab4f87710)


- Back in Shuffle, select apps on the bottom left and search for Virustotal in the search bar. 

- Click on the result to activate it and then once activated, drag into your workflow and connect the SHA256_Regex to it. 

- Click the orange "Authenticate Virustotal" button and paste your API key in the corresponding text box. Ensure the url is set to https://www.virustotal.com and click submit.

- Under find actions select Get a hash report.

![Virustotal integration](https://github.com/user-attachments/assets/a2fe8364-c9c6-4a2c-9bcd-5731ac4f739d)


For the Id, click the + and select group_0 from the SHA256_Regex list.
![SHA256_regex list](https://github.com/user-attachments/assets/bc5b60d9-9e53-4f0d-9745-2f2ec3f48e4c)

Rerun the execution and Virustotal should give similar results:
![Virus total results](https://github.com/user-attachments/assets/7fba3728-6315-4689-ba5b-cbe52d502322)
![Virus total results 2](https://github.com/user-attachments/assets/94f72e06-206d-4ada-978f-4777725375d1)

Next we will head to TheHive and click the + button in the top left corner to create a new Organization. 

The click on the organization and click on the + button to add a new user to this organization. I created 2: 
1. A Normal account with profile set to "analyst"
2. A Service account with profile set to analyst - keep in mind that you would want to create a new profile for this type of scenario in a real world application and use the Principle of Least Privilege. 

![Thehive user creation](https://github.com/user-attachments/assets/a20e4550-e264-4bff-8d4b-89b65f426f8b)

The Service account gives us an API key that we will copy to use in our Shuffle workflow.
![Thehive SOAR API key](https://github.com/user-attachments/assets/1a7ec262-95bd-4787-afba-d3934ab85828)

Follow the same steps taken to place and authorize the Virustotal node. Ensure the url is set to your Thehive private IP on port 9000 
![Hive API authentication](https://github.com/user-attachments/assets/e692d9f4-b27f-4512-9b4a-9b7dec43b05f)

Select create alert under find actions 
![Thehive node1](https://github.com/user-attachments/assets/805d2fb2-dbc0-4803-9409-f6b0de0566b3)


Set **Ssl verify** and **To file** as false and put the following info in the rest of the fields without quotes:

**Type** - "Internal"

**Tlp** - "2"

**Title** - "$exec.title" - search for title under execution argument or manually type in

**Tags** - ["T1003"] this is an array that will be using the mitre id we set in our ossec rule. - Leave the brackets and quotes for this 

**Summary** - Mimikatz Activity Detected On Host:$exec.text.win.system.computer and the process ID is:$exec.text.win.system.processID and the command line is:$exec.text.win.eventdata.commandLine

**Status** - "New"

**Soruceref** - \"Rule: 100002\"

**Source** - Wazuh

**Severity** - 2

**Pap** - 2

**Flag** - false

**Description** -Mimikatz Detected on host:$exec.text.win.system.computer from user:$exec.all_fields.data.win.eventdata.user at time:$exec.text.win.eventdata.utcTime

You can leave **Externallink** blank. 
![TheHive troubleshooting](https://github.com/user-attachments/assets/875f1e06-9fdb-4d02-9dfb-0b6fed04270b)

After rerunning our workflow, we will receive an error from TheHive. That is because we need to tell our firewall to allow all TCP traffic on port 9000. 

I only set it to allow IPv4, not IPv6 but you can set however you'd like.

![firewall](https://github.com/user-attachments/assets/5e2edc4e-9ea9-40e8-a753-a288f6baacf2)

If we rerun the workflow and sign into TheHive with the Normal account we set up we should see an alert that matches our fields we put in the TheHive node. 
![thehive alert](https://github.com/user-attachments/assets/dd736aa0-511d-472f-aa30-42f76f83803a)

The last step for this workflow will be to add an email application in shuffle so we will get notified of a security event directly via email. 

Select the email app from the list and drag into the workflow. I connected this node to virustotal instead of to TheHive so virustotal is connected directly to both.

- Set the **recipient** to whichever email you would like to use for these alerts.

- The **subject** you can make whatever you would like. I made mine Mimkatz Detected.

For the **body**:   $exec.text.win.eventdata.utcTime
            Title: $exec.title
            Host: $exec.text.win.system.computer

This will provide us with the time and date of the event, the title of the event, and the host machine that it was detected on.
![Email app - personal email used for convenience](https://github.com/user-attachments/assets/71ed174a-8414-4bd3-b5ff-9b188d724f48)

Check your inbox after the workflow is ran and you should see an alert email that looks something like this:
![Mimikatz detected email](https://github.com/user-attachments/assets/3a287741-144a-49c2-9497-85710528f547)


## New Linux Wazuh Agent
In this final section I set up another Wazuh agent with a Linux machine this time and created a new Shuffle Workflow to automate responsive actions to block an IP that had successfully SSHd into the machine. Windows is capable of responsive actions as well but in this case, I went with a Linux machine.

This is the Linux machine with Ubuntu 22.04 that I created:
![Screenshot 2024-11-09 190543](https://github.com/user-attachments/assets/40be1c8c-3c3d-479f-994e-e318a9cb0444)

Next, I created a new firewall specifically for this Linux machine that allows TCP and UDP traffic on all ports.
![Screenshot 2024-11-09 190527](https://github.com/user-attachments/assets/f984571b-a6c8-4199-8b69-1f3249eb7cdd)

I also made sure to allow my new Ubuntu machine access to the Wazuh Manager via the first firewall I set up and added a rule to allow all traffic on port 55000 which our Shuffle node will need to communicate with Wazuh.
![Add Ubuntu IP to firewall allow list](https://github.com/user-attachments/assets/2c73e46e-88b7-4cd6-b5a6-84e2724e2f9f)

Following the same steps I took for the Windows machine, I created a new agent in Wazuh for my newly created Ubuntu machine. 


## Shuffle workflow for Linux Wazuh Agent
I created a new separate workflow in shuffle using the following apps/trigger nodes:
###### **- Webhook (trigger)** to send our designated alert logs to shuffle
###### **- Http** - this application will send a curl request to the Wazuh server to obtain a token to be used later on with the Wazuh application node
###### **- Virustotal** - this will check the reputation of the ip address obtained from the webhook 
###### **- User input (trigger)** - this will send an email giving the option to block the ip address that successfully SSHd into the system
###### **- Wazuh** - this app will take the response from the User input node and forward to Wazuh to perform the responsive action

![shuffle ubuntu](https://github.com/user-attachments/assets/5ddcb0a0-9a64-4363-8f6b-1476c42c1aec)

In the ossec.conf file on the Wazuh manager, there is a list of commands that can be used that tell Wazuh to perform a specific action. We will be using the firewall-drop command.

I created the active response for firewall-drop which goes in between the "commands" and "log analysis" sections. See below for how I input that. 

Using level instead of ruleid will run this active-response for any rule with a level of 5 or higher.

Wazuh has several rules for failed SSH authentications and sign in attempts which will automatically trigger the firewall-drop active response depending on the *level* we set for the active-response which is very useful, but could potentially cause issues if there was a genuine mistake with a login attempt. 

![Editing Ossec file for commands](https://github.com/user-attachments/assets/150ce48f-b1b3-4219-8c3c-92aab05800ed)

I then added the second webhook to the ossec.conf file as it will have a different url than the first and set it up to trigger from rule 100001. 

Keep the name of both integrations as the default "shuffle", otherwise Wazuh will not know which wrapper to user for the webhook and it will not work. 

**Ensure the webhook is started in shuffle.**
![Second webhook URL ](https://github.com/user-attachments/assets/9c029e8e-15c6-4c0c-a059-3e7cf7384dee)

Then I went to the lcoal rules file which can be accessed either from the Wazuh manager machine, or on the dashboard like we did earlier for rule 100002.

Rule 100001 already existed, however, by default, it triggered from rule 5716 which is failed ssh authentication. I set mine to trigger from a successful ssh connection. 
![Local rules](https://github.com/user-attachments/assets/b727ea03-75e1-417d-8133-68d7f242d6b2)

### HTTP node
For the Http app, I renamed it to Get_API and selected get api under actions. Below is the curl command that you will need to put in the statement box. Be sure to replace  `<USER>:<PASSWORD>` with the API user credentials for the Wazuh Manager that were given when installing the Wazuh manager. 

If you need to go back to find the API user credentials, you can find it in the `wazuh-passwords.txt` file in the `~/wazuh-install-files` directory on the Wazuh Manager machine.  
![Get API for Wazuh](https://github.com/user-attachments/assets/4f473199-65c6-4847-a507-435eb4465a03)

### Virustotal node

Set the action to Get an ip address report and the IP will be the source ip obtained from the webhook. 
![Virus total Ip](https://github.com/user-attachments/assets/80416c1b-b33c-4908-afe4-192ba5b43eca)

### User Input node

I set up the User input node as follows and decided to send the Input request via email
![User input](https://github.com/user-attachments/assets/3ca32ade-c584-4acd-b567-fb885ba46aa3)

### Wazuh node

Lastly was the Wazuh app node. the Apikey field was set to our API-Key node, and the URL was our Wazuh manager URL on port 55000
![Wazuh node 1](https://github.com/user-attachments/assets/c25d06fb-40f1-4ce2-a481-2e8844363bc3)

Agents list is set to the agent.id field from the webhook. This tells Wazuh which agent to use the active response on which in this case would be agent 002. 

![Wazuh Node 2](https://github.com/user-attachments/assets/ab5b9291-55e6-4077-ba06-eacdceec81a5)

Next we fill in the command box with the appropriate command firewall-drop0. 

- **The reason for the 0 after firewall-drop is that command name is appending the timeout to the name but it is hidden. For the use in an API we need the full name.** 

	**To find the proper name of commands with an API we can check the agent control binary by going to `/var/ossec/bin` and typing `./agent_control -L`.** 


The alert box contains the source ip recieved from the webhook: `{"data":{"srcip":"$exec.all_fields.data.srcip"}}`
![Wazuh Node 3](https://github.com/user-attachments/assets/19069308-d518-4bc1-b376-382f12f9565a)

After finishing set up on all nodes in Shuffle, I SSHd into my Linux Wazuh Agent using Powershell on my main computer to test the functionality of my wokflow.
![Wazuh security events 100001](https://github.com/user-attachments/assets/96a53a00-e611-4415-b99c-732eefca6aa6)

I received the email alert from shuffle and clicked the top link to block the IP.
![Shuffle Email alert](https://github.com/user-attachments/assets/63b18a23-04b5-4595-8daf-311ecc1be5a3)

To check that the active response was executed, I looked at the active response logs on the Wazuh manager
![Active response log location and cat command](https://github.com/user-attachments/assets/d5cfee94-b2c9-4a8d-8ac7-caf24caadbeb)

This verified that my IP address was blocked.
![Active response log my ip dropped](https://github.com/user-attachments/assets/51961501-3461-4992-b1e7-4f32718bd7d8)

Also checking the Wazuh security events shows the event id 651 which is active response. 
![Wazuh security events 651](https://github.com/user-attachments/assets/b58e9aa6-0459-46fd-9944-cb8e99ce383c)

Checking powershell that I was using to SSH into my Linux machine, it shows the following: 
![SSH connection result](https://github.com/user-attachments/assets/9651cc1f-6278-47fd-9a9c-36b7e37f14bf)


This is the conclusion of the steps for this project. There are many different use cases for this type of set up but this was just one example. Shuffle can be very useful for automating certain tasks like we demonstrated in this project but its capabilities stretch far beyond what I did here. 
