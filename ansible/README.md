Installation instructions
------------ 

Install ansible galaxy collections and python dependencies:
 
```shell
  ansible-galaxy collection install yoctoalex.xc_cloud_modules
  ansible-galaxy collection install kubernetes.core
  pip3 install kubernetes
```

Create API Token. Navigate to the **Administration** page.
  
![navigate_to_administration](../assets/token_navigate.png)
  
Then open **Credentials** tab and click **Add Credentials**
  
![create_token](../assets/token_create_0.png)

Fill details and click **Generate** button
    
![fill_details](../assets/token_create_1.png)

Copy generated token to the ansible script in the evironments section. 
Here you can also configure your namespace, tenant, app prefix, etc.

```yaml
  environment:
      XC_API_TOKEN: "your_api_token"
      XC_TENANT: "console.ves.volterra.io"
      
  vars:
      namespace: "starratings"
      prefix: "star-ratings"
      domain: "star-ratings.example.com"
      vk8s: "demo-vk8s"
```

Execute ansible script with following command:

```shell
  ansible-playbook playbook.yaml -i ./hosts
```
