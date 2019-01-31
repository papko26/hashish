import sys
import os
import logging
import re
import ast
import hashlib
import random
import string
import argparse
import json
import yaml
import requests
from configparser import ConfigParser

lgr = logging.getLogger(__name__)

class vault():

    def __init__(self,
                config_file,
                vault_token_name="VAULT_TOKEN",
                config_main_section="whisperer",
                config_api_addr_option="api_addr",
                config_kv_value_option="kv_name"):

        parser = ConfigParser()

        self.separator = "=================================================================================================================================="

        if not vault_token_name in os.environ:
            lgr.critical("No {} in env".format(vault_token_name))
            sys.exit()
        if not os.path.exists(config_file):
            lgr.critical("No config file found in path {}".format(config_file))
            sys.exit()

        parser.read(config_file)

        if not parser.has_option(config_main_section, config_api_addr_option):
            lgr.critical("Config file had no mandatory option: {}".format(config_api_addr_option))
            sys.exit()

        if not parser.has_option(config_main_section, config_kv_value_option):
            lgr.critical("Config file had no mandatory option: {}".format(config_kv_value_option))
            sys.exit()
        
        self.vault_api_addr = parser[config_main_section][config_api_addr_option]
        self.vault_kv_name = parser[config_main_section][config_kv_value_option] 
        self.vault_api_token_header = {'X-Vault-Token': os.environ[vault_token_name]}
        
    def _secret_path_validator(self,path):
        """
            Internal function that validates given string to be valid for furher functions usage
        """
        if type(path) is str:
            if path[0] == "/":
                return path[1:]
            else:
                return path
        else:
            lgr.warning("Incorrect path")
            return False

    def _secret_payload_checker(self, payload):
        """
            Internal function that validates given payload to be valid for furher functions usage
            >: any arg
            <: returns given arg if its a dict, formating it to {"data":{arg}}, if not aledy
            <F: returns false if given arg is not a dic
        """
        if type(payload) is dict:
            if "data" in payload and len(payload) == 1:
                return payload
            else:
                return dict({"data":payload})
        else:
            lgr.warning("Wrong type of payload")
            return False
            



    def is_secret_exists(self, secret_path, verbose=True):
        """
            Checks if secret is exist by given path

        """
        checked_secret_path = self._secret_path_validator(secret_path)
        if not checked_secret_path:
            return False
        else:
            secret_path = checked_secret_path

        check_string = "{}{}/metadata/{}".format(self.vault_api_addr, self.vault_kv_name,secret_path)
        try:
            api_reply = requests.get(check_string, headers=self.vault_api_token_header)
        except Exception as e:
            lgr.critical("Some network or connection issues {}".format(e.args))
            return False

        if api_reply.status_code == 200:
            return True
        else:
            if verbose:
                lgr.info("Secret does not exists")
            return False


    def check_delete_secret(self, secret_path):
        """
            Deletes secret by given path
        """
        checked_secret_path = self._secret_path_validator(secret_path)
        if not checked_secret_path:
            return False
        else:
            secret_path = checked_secret_path

        if self.is_secret_exists(secret_path):
            destroy_string = "{}{}/metadata/{}".format(self.vault_api_addr, self.vault_kv_name,secret_path)
            try:
                api_reply = requests.delete(destroy_string, headers=self.vault_api_token_header)
            except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
            if api_reply.status_code == 204:
                if not self.is_secret_exists(secret_path, False):
                    return True
                else:
                    lgr.error("Command accepted, but secret not deleted (yet?) 0_o: {}".format(api_reply.content))
            else:
                lgr.error("Unexpected error when deleting: {}".format(api_reply.content))
                return False
        else:
            lgr.error("No such secret")
            return False
    

    def _create_or_update_secret(self, secret_path, payload):
        """
        Internal function for creating or updating secret by given path and payload.
        It also checks if given args are correct, and everything is goes like it should be.
        >: secret path as string
        >: payload as dict{"data":{"key":"value"}, {"key":"value"}}
        <T: returns true if action done
        <F: returns false if not, or some error occured 
        """
        checked_secret_path = self._secret_path_validator(secret_path)
        if not checked_secret_path:
            return False
        else:
            secret_path = checked_secret_path

        checked_payload = self._secret_payload_checker(payload)
        if not checked_payload:
            return False
        else:
            payload = checked_payload

        create_string ="{}{}/data/{}".format(self.vault_api_addr, self.vault_kv_name,secret_path)
        try:
            api_reply = requests.post(create_string, headers=self.vault_api_token_header, data=json.dumps(payload))
        except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False

        if api_reply.status_code == 200:
            return True
        else:
            lgr.error("Updating/Deleting of secret failed for some reason: {}".format(api_reply.content))
            return False

    def check_create_or_update_secret(self, secret_path, payload, force=False):
        """
        This one is only for creating/modifying (based on force flag) secret by given path and payload.
        It also checks if secret is really created, and was not created alredy.
        """
        if not self.is_secret_exists(secret_path):
            if self._create_or_update_secret(secret_path, payload):
                if self.is_secret_exists(secret_path):
                    return True
                else:
                    lgr.error("Command accepted, but secret not created (yet?) 0_o")
                    return False
            else:
                lgr.error("Unexpected error, when creating secret")
                return False
        else:
            if not force:
                lgr.error("Secret alredy exists. Use force=True to modify it.")
                return False
            else:
                if self._create_or_update_secret(secret_path, payload):
                    if self.is_secret_exists(secret_path):
                        return True
                    else:
                        lgr.error("Command accepted, but secret not created (yet?) 0_o")
                        return False
                else:
                    lgr.error("Unexpected error, when creating secret")
                    return False


            
    def read_secret_data(self, secret_path):
        """
        This on reads secret by given path, and returns its data
        """

        checked_secret_path = self._secret_path_validator(secret_path)
        if not checked_secret_path:
            return False
        else:
            secret_path = checked_secret_path

        if self.is_secret_exists(secret_path):
            read_string = "{}{}/data/{}".format(self.vault_api_addr, self.vault_kv_name,secret_path)
            try:
                api_reply = requests.get(read_string, headers=self.vault_api_token_header)
            except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
            if api_reply.status_code == 200:
                data=json.loads(api_reply.content.decode('utf-8'))
                return dict({"data":data['data']['data']})
            else:
                lgr.error("Unexpected error from vault")
                lgr.error(api_reply.status_code)
                lgr.error(api_reply.content)
                return False
        else:
            lgr.error("No such secret")
            return False



    def check_move_secret(self, old_path, new_path, force=False):
        """
        This one moves secret (modifying dst secret if force flag set)
        """

        checked_secret_path = self._secret_path_validator(old_path)
        if not checked_secret_path:
            return False
        else:
            old_path = checked_secret_path

        checked_secret_path = self._secret_path_validator(new_path)
        if not checked_secret_path:
            return False
        else:
            new_path = checked_secret_path

        if self.is_secret_exists(old_path):
            old_data = self.read_secret_data(old_path)
            if self.is_secret_exists(new_path):
                if not force:
                    lgr.error("Destination secret alredy exists! Use force=True to force me rewrite it.")
                    return False
                else:
                    if self.check_create_or_update_secret(new_path, old_data, force):
                        if self.check_delete_secret(old_path):
                            return True
                        else:
                            lgr.error("Destination updated, but source cant be deleted")
                            return False
                    else:
                        lgr.error("Cant update new secret")
                        return False

            else:
                if self.check_create_or_update_secret(new_path, old_data):
                    if self.is_secret_exists(new_path):
                        if self.check_delete_secret(old_path):
                            return True
                        else:
                            lgr.error("Destination created, but source cant be deleted")
                            return False
                    else:
                        lgr.error("Comand accepted, but secret not created 0_o")
                        return False
                else:
                    lgr.error("Cant create new secret")
                    return False
        else:
            lgr.error("No source secret to move")
            return False


    def check_copy_secret(self, old_path, new_path, force=False):
        """
        This one copies secret from one path to another 
        """

        checked_secret_path = self._secret_path_validator(old_path)
        if not checked_secret_path:
            return False
        else:
            old_path = checked_secret_path

        checked_secret_path = self._secret_path_validator(new_path)
        if not checked_secret_path:
            return False
        else:
            new_path = checked_secret_path

        if self.is_secret_exists(old_path):
            old_data = self.read_secret_data(old_path)
            if self.is_secret_exists(new_path):
                if not force:
                    lgr.error("Destination secret alredy exists! Use force=True to force me rewrite it.")
                    return False
                else:
                    if self.check_create_or_update_secret(new_path, old_data, force):
                        return True
                    else:
                        return False
            else:
                if self.check_create_or_update_secret(new_path, old_data):
                    if self.is_secret_exists(new_path):
                        return True
                    else:
                        lgr.error("Comand accepted, but secret not created 0_o")
                        return False
                else:
                    lgr.error("Cant create new secret")
                    return False
        else:
            lgr.error("No source secret to move")
            return False


    def _secret_path_dir_fixer(self, path):
        """
        internal function to check and fix if path given without slash
        """
        if not path.endswith('/'):
            return (path + "/")
        else:
            return (path)

    def _path_without_level(self, base, path):
        """
        internal function to retrive path part without indent level for recursive copy
        """
        levels_in_path = len(base.split("/"))
        return '/'.join(path.split("/")[-levels_in_path:])

    def _secret_name_by_path(self,path):
        """
        internal function to get only secret name without path
        """
        return path.split("/")[-1]

    def check_copy_secret_dir(self, src_path, dst_path, no_struct=False, force=False):
        """
        This one copies secrets directory recursively. 
        If flag no_struct passed = copies only secrets, without dirs structure
        If flag force passwd = rewrite secrets with duplicate names
        """
        src_path = self._secret_path_dir_fixer(src_path)
        dst_path = self._secret_path_dir_fixer(dst_path)
        status = -1
        secrets = self.list_directory(src_path)
        if secrets:
            status = len(secrets)
            for secret in secrets:
                secret_name = self._secret_name_by_path(secret)
                if no_struct:
                    new_target_secret_path = dst_path+secret_name
                else:
                    new_target_secret_path = dst_path+self._path_without_level(dst_path,secret)
                if self.check_copy_secret(secret, new_target_secret_path, force):
                    status -=1
        else:
            lgr.error("No secrets by given path")
            return False

        if not status:
            return True
        else:
            lgr.error("Something went worng (failed tasks count:{})".format(status))
            return False


    def check_move_secret_dir(self, src_path, dst_path, no_struct=False, force=False):
        """
        This one moves secrets directory recursively. 
        If flag no_struct passed = moves only secrets, without dirs structure
        If flag force passwd = rewrite secrets with duplicate names
        """
        src_path = self._secret_path_dir_fixer(src_path)
        dst_path = self._secret_path_dir_fixer(dst_path)
        status = -1
        secrets = self.list_directory(src_path)
        if secrets:
            status = len(secrets)
            for secret in secrets:
                secret_name = self._secret_name_by_path(secret)
                if no_struct:
                    new_target_secret_path = dst_path+secret_name
                else:
                    new_target_secret_path = dst_path+self._path_without_level(dst_path,secret)
                if self.check_copy_secret(secret, new_target_secret_path, force):
                    status -=1
            if not status:
                if self.check_delete_secret_dir(src_path):
                    return True
                else:
                    lgr.error("DST secrets created, but SRC cant be deleted")
                    return False
            else:
                lgr.error("Something went worng (failed tasks count:{})".format(status))
                return False
        else:
            lgr.error("No secrets by given path")
            return False

    def check_delete_secret_dir(self, secret_dir_path):
        """
        This one deletes secrets directory recursively. 
        """
        secret_dir_path = self._secret_path_dir_fixer(secret_dir_path)
        secrets = self.list_directory(secret_dir_path)
        status = -1
        if secrets:
            status = len(secrets)
            for secret in secrets:
                if self.check_delete_secret(secret):
                    status -= 1
            if not status:
                return True
            else:
                return False
        else:
            lgr.error("No secrets by given path")
            return False

        

    def list_directory(self, secret_dir_path, with_data=False, depth=1000, silent_error=False):
        """
        This one lists every secret and for directory
        If flag with_data passed - it also prints every secret data
        """
        secret_dir_path = self._secret_path_dir_fixer(secret_dir_path)

        custom_request = 'LIST'
        list_string = "{}{}/metadata/{}".format(self.vault_api_addr, self.vault_kv_name,secret_dir_path)
        reply = []
        try:
            api_reply = requests.request(custom_request, list_string, headers=self.vault_api_token_header)
        except Exception as e:
            lgr.critical("Some network or connection issues {}".format(e.args))
            return False
        if api_reply.status_code == 200:
            data = json.loads(api_reply.content.decode('utf-8'))
            keys = data['data']['keys']
            for key in keys:
                if depth>=0:
                    if key[-1:] == "/" and depth > 1:
                        reply = reply + self.list_directory(secret_dir_path+key, with_data, depth)
                    else:
                        if with_data:
                            reply.append({secret_dir_path+key : self.read_secret_data(secret_dir_path+key)})
                        else:
                            reply.append(secret_dir_path+key)
                    depth=depth-1
            return reply
        else:
            if not silent_error:
                lgr.error("No such path!")
            return False


    def human_readable_list_directory(self,secret_dir_path, with_data, depth):
        """
        This one lists every secret for directory in human readable format
        """        
        data = self.list_directory(secret_dir_path, with_data, depth)
        for item in data:
            print (item)
            print ()

    def _acl_name_validator(self, acl_name):
        """
        Internal function that validates given string to be valid for furher functions usage
        """
        if type(acl_name) is str:
            return acl_name
        else:
            lgr.warning("Incorrect acl_name")
            return False
        

    def is_policy_exists(self, acl_name, verbose=True):
        """
        Takes acl_name as arg, and check if it exists
        """

        checked_acl= self._acl_name_validator(acl_name)
        if not checked_acl:
            return False
        else:
            acl_name = checked_acl

        list_string = "{}sys/policies/acl/{}".format(self.vault_api_addr,acl_name)
        try:
            api_reply = requests.get(list_string, headers=self.vault_api_token_header)
        except Exception as e:
            lgr.critical("Some network or connection issues {}".format(e.args))
            return False
        if api_reply.status_code == 200:
            return True
        else:
            if verbose:
                lgr.info("Secret does not exists")
            return False

    def read_policy_data(self, acl_name):
        """
        Takes acl_name as arg, and returns it data
        """
        checked_acl= self._acl_name_validator(acl_name)
        if not checked_acl:
            return False
        else:
            acl_name = checked_acl

        if self.is_policy_exists(acl_name):
            get_string = "{}sys/policies/acl/{}".format(self.vault_api_addr,acl_name)
            try:
                api_reply = requests.get(get_string, headers=self.vault_api_token_header)
            except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
            if api_reply.status_code == 200:
                data=json.loads(api_reply.content.decode('utf-8'))
                return dict(data['data'])
            else:
                lgr.error("Policy exists, but I cant get it 0_o")
                return False
        else:
            lgr.error("No such policy")
            return False

    def _create_or_update_policy(self, acl_name, payload):
        """
        Internal, that creates any policy by given name and payload
        payload example:
        {'name': 'test1','policy': 'path "GI/data/services/test1/*" {\n    capabilities = ["create", "read", "list"]\n}'}))
        """
        create_string = "{}sys/policies/acl/{}".format(self.vault_api_addr,acl_name)
        try:
            api_reply = requests.put(create_string, headers=self.vault_api_token_header, data=json.dumps(payload))
        except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
        if api_reply.status_code == 204:
            return True
        else:
            lgr.error("Unexpected error when creating policy")
            return False

    def check_create_or_update_policy(self, acl_name, payload, force=False):
        """
        This one creates policy and check if it created
        """
        if force or not self.is_policy_exists(acl_name):
            self._create_or_update_policy(acl_name, payload)
            if self.is_policy_exists(acl_name):
                return True
            else:
                lgr.error("Command set, but not created 0_o (yet?)")
                return False
        else:
            lgr.error("Policy exists, but force flag not set. Wont replace it")
            return False

    def check_delete_policy(self, acl_name):
        """
        This one deletes policy
        """
        if self.is_policy_exists(acl_name):
            delete_string = "{}sys/policies/acl/{}".format(self.vault_api_addr,acl_name)
            try:
                api_reply = requests.delete(delete_string, headers=self.vault_api_token_header)
            except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
            if api_reply.status_code == 204:
                if not self.is_policy_exists(acl_name, False):
                    return True
                else:
                    lgr.error("Policy was not deleted for some reasons")
                    return False
            else:
                lgr.error("Unexpected error when deleting policy")
                return False
        else:
            lgr.error("Policy does not exists!")
            return False

    def check_copy_policy(self, old_acl, new_acl, force=False, rename_inside=True):
        """
        Use it to copy policy.
        force - to replace any dst policy with same name
        rename_inside - to rename "name" inside acl data
        """
        if self.is_policy_exists(old_acl):
            data = self.read_policy_data(old_acl)
            if data:
                if rename_inside:
                    if "name" in data:
                        data.update({"name":new_acl})
                    else:
                        lgr.error("No name inside policy, this is minor fail, I will continue")
                        
                if self.check_create_or_update_policy(new_acl,data, force):
                    return True
                else:
                    lgr.error("Cant create dst policy")
                    return False
            else:
                lgr.error("Cant read src policy for some reason")
                return False

    def check_rename_policy(self, old_acl, new_name, force=False, rename_inside=True):
        """
        Use it to rename policy.
        force - to replace any dst policy with same name
        rename_inside - to rename "name" inside acl data
        """
        if self.is_policy_exists(old_acl):
            data = self.read_policy_data(old_acl)
            if data:
                if rename_inside:
                    if "name" in data:
                        data.update({"name":new_name})
                    else:
                        lgr.error("No name inside policy, this is minor fail, I will continue")

                if self.check_create_or_update_policy(new_name,data, force):
                    if self.check_delete_policy(old_acl):
                        return True
                    else:
                        lgr.error("Cant delete src policy")
                        return False
                else:
                    lgr.error("Cant create dst policy")
                    return False
            else:
                lgr.error("Cant read src policy for some reason")
                return False


    def list_policies(self):
        list_string = "{}sys/policy".format(self.vault_api_addr)
        try:
            api_reply = requests.get(list_string, headers=self.vault_api_token_header)
        except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
        reply = []
        if api_reply.status_code == 200:
                data=json.loads(api_reply.content.decode('utf-8'))
                all_policies = data['policies']
                for policy in all_policies:
                    reply.append(self.read_policy_data(policy))
                return reply
        else:
                lgr.error("Unexpected reply from vault")
                return False

    def human_readable_list_policies(self, with_data=False):
        data = self.list_policies(with_data)
        for item in data:
            print (item)
            print (self.separator)

    def is_approle_exists(self, approle_name):
        """
        Just check if approle with such name alredy exists T/F
        """
        get_string = "{}auth/approle/role/{}".format(self.vault_api_addr,approle_name)
        try:
            api_reply = requests.get(get_string, headers=self.vault_api_token_header)
        except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
        if api_reply.status_code == 200:
            return True
        else:
            return False

    def read_approle_data(self, approle_name):
        """
        Get approle by it name (will return dict {approle_name:data})
        """
        if self.is_approle_exists(approle_name):
            get_string = "{}auth/approle/role/{}".format(self.vault_api_addr,approle_name)
            try:
                api_reply = requests.get(get_string, headers=self.vault_api_token_header)
            except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
            if api_reply.status_code == 200:
                    data=json.loads(api_reply.content.decode('utf-8'))
                    return data['data']
            else:
                lgr.error("Approle exists, but cant read it 0_o")
                return False
        else:
            lgr.error("Approle does not exists!")
            return False
    def role_create_payload_generator(self, policies_array, secret_id_ttl, token_num_uses, token_ttl, token_max_ttl, bind_secret_id=True, secret_id_bound_cidrs=[],token_bound_cidrs=[],secret_id_num_uses =0,period="",enable_local_secret_ids=False):
        """
        Smal duty function to not go mad while trying to remember all approle options
        """
        data = {"policies":policies_array, "secret_id_ttl":secret_id_ttl, "token_num_uses":token_num_uses, "token_ttl":token_ttl, "token_max_ttl":token_max_ttl, "secret_id_bound_cidrs":secret_id_bound_cidrs, "token_bound_cidrs":token_bound_cidrs, "secret_id_num_uses":secret_id_num_uses, "period":period, "enable_local_secret_ids":enable_local_secret_ids}
        return data

    
    def _create_or_update_approle(self, approle_name, approle_data):
        """
        Internal for creating or updating approle by given data
        """
        create_string = "{}auth/approle/role/{}".format(self.vault_api_addr,approle_name)
        try:
                api_reply = requests.post(create_string, headers=self.vault_api_token_header, data=json.dumps(approle_data))
        except Exception as e:
            lgr.critical("Some network or connection issues {}".format(e.args))
            return False
        if api_reply.status_code == 204:
            return True
        else:
            lgr.error("Cant create approle")
            return False

    def check_create_or_update_approle(self, approle_name, approle_data, check_policies=True, force=False):
        """
        Creates or updates approle by given name and upload
        change check_policies flag for check or not is requested policies alredy exists
        change force flag, for create approle even if it alredy exist
        """
        if check_policies and "policies" in approle_data:
            for policy in approle_data['policies']:
                if not self.is_policy_exists(policy):
                    lgr.error("Create policy for {} first".format(policy))
                    return False
        
        if force or not self.is_approle_exists(approle_name):
            if self._create_or_update_approle(approle_name, approle_data):
                if self.is_approle_exists(approle_name):
                    return True
                else:
                    lgr.error("Command accepted, but approle not created 0_o (yet?)")
                    return False
            else:
                lgr.error("Approle exists, but force flag not set. Wont replace it")
                return False


    def list_approles(self, with_data=False):
        """
        List all existing approles, with contents, or not
        """
        custom_request = 'LIST'
        list_string = "{}auth/approle/role".format(self.vault_api_addr)
        try:
            api_reply = requests.request(custom_request,list_string, headers=self.vault_api_token_header)
        except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
        reply = []
        if api_reply.status_code == 200:
            data=json.loads(api_reply.content.decode('utf-8'))
            for key in data['data']['keys']:
                if with_data:
                    reply.append({key:{"data":self.read_approle_data(key)}})
                else:
                    reply.append(key)
            return reply
        else:
            lgr.error("Unexpected reply from vault")
            return False

    def human_readable_list_approles(self, with_data=False):
        for item in self.list_approles(with_data):
            print (item)
            print (self.separator)

    def check_delete_approle(self, approle_name):
        """
        Delete approle by its name
        """
        if self.is_approle_exists(approle_name):
            delete_string = "{}auth/approle/role/{}".format(self.vault_api_addr,approle_name)
            try:
                api_reply = requests.delete(delete_string, headers=self.vault_api_token_header)
            except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
            if api_reply.status_code == 204:
                if not self.is_approle_exists(approle_name):
                    return True
                else:
                    lgr.error("Request sent, but role not deleted (yet?) 0_o")
                    return False
        else:
            lgr.error("No such approle")
            return False

    def check_rename_approle(self, old_approle, new_approle, force=False, check_policies=True):
        """
        Rename approle. Set force flag to replace dst approle, if it alredy exists
        """
        if force or not self.is_approle_exists(new_approle):
            if self.is_approle_exists(old_approle):
                data = self.read_approle_data(old_approle)
                if data:
                    if self.check_create_or_update_approle(new_approle, data, force=force, check_policies=check_policies):
                        if self.check_delete_approle(old_approle):
                            return True
                        else:
                            lgr.error("New approle created, but old not deleted")
                            return False
                    else:
                        lgr.error("Cant create new approle")
                        return False
                else:
                    lgr.error("Cant read src approle")
                    return 
            else:
                lgr.error("Src approle dont exists")
                return False
        else:
            lgr.error("Approle with such name alredy exist, but force flag not set. Wont replace it")
            return False


    def token_to_accessor(self, token):
        """
        Pass token and get it's accessor
        """
        lookup_string = "{}auth/token/lookup".format(self.vault_api_addr)
        try:
            api_reply = requests.post(lookup_string, headers=self.vault_api_token_header, data=json.dumps({"token": token}))
        except Exception as e:
            lgr.critical("Some network or connection issues {}".format(e.args))
            return False
        if api_reply.status_code == 200:
            data = json.loads(api_reply.content.decode('utf-8'))
            return data['data']['accessor']
        else:
            lgr.error("Looks like token does not exists")
            return False

    def token_name_to_accessors(self, token_name, verbose=True):
        """
        Pass token_name and get all associated accesors
        """
        reply = []
        tkndl = self.list_tokens()
        for tknd in tkndl:
            data = self.read_token_data(tknd)
            if data['data']['display_name'] == "token-{}".format(token_name):
                reply.append(tknd)
        if not reply:
            if verbose:
                lgr.error("No tokens with such name")
            return False
        else:
            return reply

    def list_tokens(self, with_data=False):
        """
        List all existing tokens (and its data if with_data dlag is set)
        """
        custom_request = 'LIST'
        list_string = "{}auth/token/accessors".format(self.vault_api_addr)
        try:
            api_reply = requests.request(custom_request,list_string, headers=self.vault_api_token_header)
        except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
        reply = []
        if api_reply.status_code == 200:
            data=json.loads(api_reply.content.decode('utf-8'))
            for key in data['data']['keys']:
                if with_data:
                    reply.append(self.read_token_data(key))
                else:
                    reply.append(key)
            return reply
        else:
            lgr.error("Unexpected reply from vault")
            return False

    def is_token_exists(self, token_accessor, verbose=True):
        """
        Check if token exists, by its accessor
        """
        lookup_string = "{}auth/token/lookup-accessor".format(self.vault_api_addr)
        try:
            api_reply = requests.post(lookup_string, headers=self.vault_api_token_header, data=json.dumps({"accessor": token_accessor}))
        except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
        if api_reply.status_code == 200:
            return True
        else:
            if verbose:
                lgr.error("Token does not exist")
            return False

    def read_token_data(self, token_accessor):
        """
        Read token, by its accessor
        """
        if self.is_token_exists(token_accessor):
            lookup_string = "{}auth/token/lookup-accessor".format(self.vault_api_addr)
            try:
                api_reply = requests.post(lookup_string, headers=self.vault_api_token_header, data=json.dumps({"accessor": token_accessor}))
            except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
            if api_reply.status_code == 200:
                data = json.loads(api_reply.content.decode('utf-8'))
                return dict({"data":data['data']})
            else:
                lgr.error("Unexpected error")
                return False
        else:
            return False

    def token_payload_generator(self, display_name, num_uses, policies_array, ttl ,meta_map={}, no_parent = False, id="", role_name="", no_default_policy=False, renewable=True, explicit_max_ttl="", period=""):
        """
        Smal internal function to not go mad while trying to remember all token options
        """
        data = {"display_name":display_name, "num_uses":num_uses, "policies":policies_array, "ttl":ttl, "meta":meta_map, "no_parent":no_parent, "id":id, "role_name":role_name, "no_default_policy":no_default_policy, "renewable":renewable, "explicit_max_ttl":explicit_max_ttl, "period":period}
        return data

    def create_token(self, payload):
        """
        Create token using payload (you may use token_payload_generator)
        PS: No point to check_delete implementation, only accessor and token are uniq
        """
        lookup_string = "{}auth/token/create".format(self.vault_api_addr)
        try:
            api_reply = requests.post(lookup_string, headers=self.vault_api_token_header, data=json.dumps(payload))
        except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
        if api_reply.status_code == 200:
            data = json.loads(api_reply.content.decode('utf-8'))
            return data['auth']['client_token']
        else:
            lgr.error("Unexpected error: {}".format(api_reply.content.decode('utf-8')))
            return False


    def check_delete_token(self, token_accessor):
        """
        Delete token, and check if its really done
        """
        if self.is_token_exists(token_accessor):
            lookup_string = "{}auth/token/revoke-accessor".format(self.vault_api_addr)
            try:
                api_reply = requests.post(lookup_string, headers=self.vault_api_token_header, data=json.dumps({"accessor": token_accessor}))
            except Exception as e:
                lgr.critical("Some network or connection issues {}".format(e.args))
                return False
            if api_reply.status_code == 204:
                if not self.is_token_exists(token_accessor, False):
                    return True
                else:
                    lgr.error("Request sent, but token not deleted (yet?) 0_o")
                    return False
            else:
                lgr.error("Unexpected error(may be token alredy deleted by ttl?)")
                return False
        else:
            lgr.error("Token does not exist")
            return False


    def human_readable_list_tokens(self, with_data=False):
        for item in self.list_tokens(with_data):
            print (item)
            print (self.separator)

#=================================================================================================================
class vault_service_user():
    path_till_user = False
    path_username = False
    path_group = False
    path_service = False
    vault_policy_path = False
    record_path_n_cap = []

    vault_secrets = []
    desired_secrets = []

    def __init__(self, vault):
        """to init service_user class, you need to pass vault object from whisperer"""
        self.vault = vault

    def _strip_shit(self, data, shitlist):
        for item in shitlist:
            data = data.replace(item, "")
        return data

    def _parse_hcl(self, data):
        """hcl lib replacement"""
        parced_hcl = []
        full_regex = r"path [\s\S]*?}"
        path_regex = r"path (.*?){"
        cap_regex= r"capabilities.*=.*\[(.*)]"
        #find every policy record
        paths_and_caps = re.findall(full_regex, data)
        for pnc in paths_and_caps:
            #find path in record
            path = re.findall(path_regex, pnc)
            #find capibilities list in record
            cap = re.findall(cap_regex, pnc)
            #its expected that its only one path and cap list per record
            if len(cap) == len (path) == 1:
                path = self._strip_shit(path[0], ['"',"'"," "])
                cap = (self._strip_shit(cap[0], ['"',"'"," "])).split(",")
                parced_hcl.append((pnc, path, cap))
            else:
                return False
        return parced_hcl

    def _parse_path(self, path_till_user):
        """Internal to parse given path to class values (external usage to return paresed data, not status)"""

        if path_till_user[-1:] is not "/":
            path_till_user = "{}/".format(path_till_user)

        self.path_till_user = path_till_user
        path_components = path_till_user.split("/")
        #naming policy: first two symbols is service data.
        #structure expected to be as: .../s/g/u/...
        services = [s for s in path_components if "s_" in s[:2]]
        groups = [g for g in path_components if "g_" in g[:2]]
        users = [u for u in path_components if "u_" in u[:2]]
        if len(services) is not 1:
            print ("Invalid user. It has more/less than one service")
            return False
        if len(groups) is not 1:
            print ("Invalid user. It has more/less than one group")
            return False
        if len(users) is not 1:
            print ("Invalid user. It has more/less than one user")
            return False
        
        try:
            self.path_service = services[0][2:]
            self.path_group = groups[0][2:]
            self.path_username = users[0][2:]
        except Exception as e:
            print ("Path to user is invalid: {}".format(path_till_user))
            return False
        return True

    def _load_policy(self):
        "Internal wrapper to load policy inside class vars"
        self.policy_path = "{}/data/{}*".format(self.vault.vault_kv_name, self.path_till_user)
        if self.vault.is_policy_exists(self.path_username, False):
            policy_data = self.vault.read_policy_data(self.path_username)
            self.record_path_n_cap = self._parse_hcl(policy_data["policy"])
            return True
        else:
            return False

    def _compile_policy_payload(self, capabilities):
        """Internal wrapper for policy payload"""
        #Its ugly, but I donno a better way =(
        caps_string = '{{ \n   capabilities = {} \n }}'.format(str(capabilities).replace("'","\""))
        policy_string = '\npath \"{}\" {}'.format(self.policy_path, caps_string)
        payload = {'name': self.path_username ,'policy': policy_string}
        return payload

    def _update_policy(self, capabilities, replace_existing_record_if_exists=False):
        """Internal wrapper to update existing policy"""
        new_payload = self._compile_policy_payload(capabilities)
        old_payload = self.vault.read_policy_data(self.path_username)
        if not replace_existing_record_if_exists:
            multi_policy =  "{}\n{}".format(old_payload["policy"], new_payload["policy"])
            multi_payload = {'name': self.path_username,'policy': multi_policy }
            return self.vault.check_create_or_update_policy(self.path_username, multi_payload, force=True)
        else:
            for rec, path, cap in self.record_path_n_cap:
                if self.policy_path in path:
                    old_payload["policy"] = old_payload["policy"].replace(rec, "")
            multi_policy =  "{}\n{}".format(old_payload["policy"], new_payload["policy"])
             #dirty workaround for whitespace bug:
            multi_policy = "\n".join([ll.rstrip() for ll in multi_policy.splitlines() if ll.strip()])
            multi_payload = {'name': self.path_username,'policy': multi_policy }

            return self.vault.check_create_or_update_policy(self.path_username, multi_payload, force=True)

    def _check_desired_policy_record(self, capabilities):
        """Internal to check if desired service record is alredy exists"""
        #Check if we got desired path in loaded data
        for rec, path, cap in self.record_path_n_cap:
            if self.path_till_user in path:
                #Check if this record had desired caps
                if not set(capabilities).symmetric_difference(cap):
                    return True
        return False
            

    def sync_policy(self, capabilities=["read", "list"], create_if_not_exist=True):
        """Logical method to sync policy records to be actual with current service and user"""
        if self._load_policy():
            if self._check_desired_policy_record(capabilities):
                #Desired policy record alredy exist. Nothing to do here
                self._load_policy()
                return True
            else:
                #Desired policy record is corrupted. It need to be replaced
                if self._update_policy(capabilities,True):
                    self._load_policy()
                    return True
                else:
                    return False
        else:
            #Policy does not exist for this user. Lets create new one
            if self.vault.check_create_or_update_policy(self.path_username, self._compile_policy_payload(capabilities)):
                self._load_policy()
                return True
            else:
                return False


    def clear_policy(self):
        self._load_policy()
        deprecated_policies = [tripple for tripple in self.record_path_n_cap if self.policy_path in tripple[1]]
        self.record_path_n_cap = [item for item in self.record_path_n_cap if item not in deprecated_policies]
        if self.record_path_n_cap:
            payload = self.vault.read_policy_data(self.path_username)
            for rec, path, cap in deprecated_policies:
                payload["policy"] = payload["policy"].replace(rec, "")
                print ("Deleting policy record")
                return self.vault.check_create_or_update_policy(self.path_username, payload, force=True)
        else:
            print ("Policy is empty. Deleting it")
            self.vault.check_delete_policy(self.path_username)
            return True

    def args_to_path(self, pre_path, username, groupname, servicename):
        if "/" in username + groupname + servicename:
            return False #we cant hawe slashes in args

        if not "u_" in username[:2]:
            username = "u_{}".format(username)
        if not "g_" in groupname[:2]:
            groupname = "g_{}".format(groupname)
        if not "s_" in servicename[:2]:
            servicename = "s_{}".format(servicename)
        return "{}/{}/{}/{}/".format(pre_path,servicename,groupname,username)


    def is_user_alredy_exists(self):
        """internal to check if user alredy exists"""
        user_secrets = self.vault.list_directory(self.path_till_user, with_data=False, silent_error=True)
        if user_secrets:
            return True
        else:
            return False

    def load_secrets(self):
        if self.is_user_alredy_exists():
            user_secrets = self.vault.list_directory(self.path_till_user, with_data=False)
            for secret in user_secrets:
                secret_name = secret.split("/")[-1]
                secret_data = self.vault.read_secret_data(secret)
                self.vault_secrets.append({secret_name:secret_data})
            return True
        else:
            print ("User does not exists!")
            return False

    def showtime(self):
        print ("path_till_user: {}".format(self.path_till_user))
        print ("path_username: {}".format(self.path_username))
        print ("path_group: {}".format(self.path_group))
        print ("path_service: {}".format(self.path_service))
        print ("vault_secrets_list: {}".format(self.vault_secrets))
        print ("desired_secrets_list: {}".format(self.desired_secrets))
        print ("record_path_n_cap: {}".format(self.record_path_n_cap))
        print ("===============")

    def load_policy(self):
        "Wrapper to load policy inside class vars"
        policy_data = self.vault.read_policy_data(self.path_username)
        if policy_data:
            self.record_path_n_cap = self._parse_hcl(policy_data["policy"])
            return True
        else:
            return False

    def reload_user(self, path_till_user, silent=False):
        if self._parse_path(path_till_user):
            self.vault_policy_path = False
            self.vault_secrets = []
            self.record_path_n_cap = []
            return self.load_user(path_till_user, silent)

    def load_user(self, path_till_user, silent=False):
        if self._parse_path(path_till_user):
            if self.is_user_alredy_exists():
                self.load_secrets()
                self.load_policy()
            else:
                if not silent:
                    print("No such user")
                return False
        else:
            raise RuntimeError('Cant parse given path')

    def delete_myself(self):
        """Delete alredy loaded user from vault"""
        self.vault.check_delete_secret_dir(self.path_till_user)
        self.clear_policy()
        self.path_till_user = False
        self.path_username = False
        self.path_group = False
        self.path_service = False
        self.creds_username = False
        self.password = False
        self.vault = False
        self.policy_path = False
        self.secrets = []
        self.vault_secrets = []
        return True


    def create_user(self):
        if not self.is_user_alredy_exists():
            for secret in self.desired_secrets:
                secret_name = list(secret.keys())[0]
                self.vault.check_create_or_update_secret(self.path_till_user+secret_name,secret[secret_name])
            self.sync_policy()
            return True
        else:
            print ("User is alredy exists!")
            return False


    
    def sync_user(self, path_till_user, secrets=[], strict=False, replace=True):
        """
        Universal method to create or update all data about service user
        generate_creds - if set to true it will generate creds for user
        strict - if set to true it will delete all old creds and set only desired
        replace - if set to true, it will replace conflicting creds by new data
        """

        self.desired_secrets = secrets

        if self._parse_path(path_till_user):
            if self.is_user_alredy_exists():

                #OK, user exists in vault. Lets load it first.
                try:
                    self.load_user(path_till_user)
                except RuntimeError as e:
                    print ("Oh shi: {}".format(e.args))
                    return False
                
                if not strict:
                    #if not strict mode, just append new secrets
                    for secret in self.desired_secrets:
                        if secret not in self.vault_secrets:
                            secret_name = list(secret.keys())[0]
                            self.vault.check_create_or_update_secret(self.path_till_user+secret_name,secret[secret_name]["data"], force=replace)
                    self.reload_user(self.path_till_user)
                    if not self.vault_secrets and not self.desired_secrets:
                        self.delete_myself()
                    return True

                else:
                    #strict mode: remove all secrets and add listed
                    if self.vault.check_delete_secret_dir(self.path_till_user):
                        for secret in self.desired_secrets:
                            secret_name = list(secret.keys())[0]   
                            self.vault.check_create_or_update_secret(self.path_till_user+secret_name,secret[secret_name], force=replace)
                        self.reload_user(self.path_till_user)
                        if not self.vault_secrets and not self.desired_secrets:
                            self.delete_myself()
                        return True

                    else:
                        print ("cant delete user old secrets")
                        return False
            else:
                #Create it from scratch
                self.create_user()
                self.reload_user(self.path_till_user)
                if not self.vault_secrets and not self.desired_secrets:
                    if self.delete_myself():
                        return True
                    else:
                        return False
                return True

class HashiParse(object):

    args = {}

    def __init__(self):
        parser = argparse.ArgumentParser(usage='''HashiSH <command> [<args>]

Every *service* had its own subfolder with *groups* (e.g .../services/s_databases/*) .
Every *group* had its *service_users* (e.g .../services/s_databases/g_developers/*)
Every *service_user* had its own subpath with secrets (e.g .../services/s_databases/g_developers/u_verkhoglyadus/*)

So this tool helps to work with it, without getting mad.

USAGE:
Set path to config file first:
    --vault_config /path/to/config.conf

Then select action command.

Action commands are:
   create     Create service user records in Vault
   delete     Delete service user records in Vault
   sync       Sync service user with given data in Vault
   apply      Apply service user/s from yaml file in Vault

''')
        parser.add_argument('command', help='Subcommand to run')
        parser.add_argument('--config', "-c", help='path to vault config (in vault whisperer format)', required=True)
        args = parser.parse_args(sys.argv[1:4])
        if not hasattr(self, args.command):
            print ('Unrecognized command')
            parser.print_help()
            exit(1)
        self.args.update(vars(args))
        getattr(self, args.command)()

    def create(self):
        preparser = argparse.ArgumentParser(description='Detect desired create action')
        preparser.add_argument('create_type', choices=['user', 'token'])
        ct = vars(preparser.parse_args(sys.argv[4:5]))
        self.args.update(ct)
        if ct.get("create_type") == "user":
            parser = argparse.ArgumentParser(description='Create service user or token in Vault')
            parser.add_argument('--service','-s', required=True)
            parser.add_argument('--name','-n', required=True)
            parser.add_argument('--group','-g', required=True)
            parser.add_argument('--gen_creds', required=False, action="store_true")
            parser.add_argument('--append_secret', required=False)
            parser.add_argument('--generate_hashes', required=False, action="store_true")
            self.args.update(vars(parser.parse_args(sys.argv[5:])))
        elif ct.get("create_type") == "token":
            parser = argparse.ArgumentParser(description='Create token in Vault')
            parser.add_argument('--name','-n', required=True)
            parser.add_argument('--policies', required=True)
            parser.add_argument('--ttl', required=False,default=0, type=int, nargs='?')
            parser.add_argument('--num_uses', required=False,default=1, type=int, nargs='?')
            self.args.update(vars(parser.parse_args(sys.argv[5:])))

    def delete(self):
        preparser = argparse.ArgumentParser(description='Detect desired delete action')
        preparser.add_argument('create_type', choices=['user', 'token'])
        ct = vars(preparser.parse_args(sys.argv[4:5]))
        self.args.update(ct)
        if ct.get("create_type") == "user":
            parser = argparse.ArgumentParser(description='Delete service user records in Vault')
            parser.add_argument('--service','-s', required=True)
            parser.add_argument('--name','-n', required=True)
            parser.add_argument('--group','-g', required=True)
            self.args.update(vars(parser.parse_args(sys.argv[5:])))
        elif ct.get("create_type") == "token":
            parser = argparse.ArgumentParser(description='Delete token from Vault')
            parser.add_argument('--name','-n', required=True)
            self.args.update(vars(parser.parse_args(sys.argv[5:])))
            




    def sync(self):
        preparser = argparse.ArgumentParser(description='Detect desired create action')
        preparser.add_argument('create_type', choices=['user'])
        ct = vars(preparser.parse_args(sys.argv[4:5]))
        self.args.update(ct)
        parser = argparse.ArgumentParser(description='Sync service user with given data in Vault')
        parser.add_argument('--service','-s', required=True)
        parser.add_argument('--name','-n', required=True)
        parser.add_argument('--group','-g', required=True)
        parser.add_argument('--strict', required=False, action="store_true")
        parser.add_argument('--replace', required=False, action="store_true")
        parser.add_argument('--regen_creds','--gen_creds', required=False, action="store_true")
        parser.add_argument('--append_secret', required=False)
        parser.add_argument('--generate_hashes', "--regenerate_hashes", required=False, action="store_true")
        self.args.update(vars(parser.parse_args(sys.argv[5:])))

    def apply(self):
        preparser = argparse.ArgumentParser(description='Detect desired create action')
        preparser.add_argument('create_type', choices=['user'])
        ct = vars(preparser.parse_args(sys.argv[4:5]))
        self.args.update(ct)
        parser = argparse.ArgumentParser(description='Apply service user/s from yaml file in Vault')
        parser.add_argument('--file','-f', required=True)
        self.args.update(vars(parser.parse_args(sys.argv[5:])))
    



class hashish():
    service_users = []
    args = False
    vault = False
    parsed_su_config = {}
    parsed_config = {}
    config_main_section="hashish"
    config_options = ["creds_containing_secret", "password_containing_value", "username_containing_value", "generated_pass_length"]

    def __init__(self):
        hp = HashiParse()
        self.vault = vault(hp.args.get('config'))

        cparser = ConfigParser()
        cparser.read(hp.args.get('config'))
        for option in self.config_options:
            if not cparser.has_option(self.config_main_section, option):
                print ("No {} option in config file!")
                sys.exit(1)
            else:
                self.parsed_config.update({option:cparser[self.config_main_section][option]})

        self.args = hp.args
        config = self.args.get('file')
        if config:
            try:
                with open(config) as cnf:
                    self.parced_config = yaml.load(cnf)
            except Exception as error:
                print("Cant parse yaml {}".format(error.args))
                sys.exit(1)
        
        
        

        sync_actions = ["create", "delete", "sync", "apply"]
        for item in sync_actions:
            if item in self.args.get("command"):
                service = self.args.get("service")
                group = self.args.get("group")
                user = self.args.get("name")
                generate_creds = self.args.get("gen_creds")
                generate_hash = self.args.get("generate_hashes")
                append_secret = self.args.get("append_secret")
                replace = self.args.get("replace")
                regen_creds = self.args.get("regen_creds")
                strict = self.args.get("strict")
                policies =  self.args.get("policies")
                ttl =  self.args.get("ttl")
                num_uses =  self.args.get("num_uses")
                create_type =  self.args.get("create_type")

                if create_type == "user":
                    su = vault_service_user(self.vault)
                    custom_secrets = []
                    path = su.args_to_path("services", user, group, service)
                    su.load_user(path, silent=True)

                if item == "create":
                    if create_type == "token":
                        if not self.is_token_exists_by_name(user):
                            token = self.issue_token(user, policies, ttl, num_uses)
                        else:
                            print("Token with such name is alredy exists!")
                            sys.exit(1)
                        if token:
                            print(token)
                            sys.exit(0)
                        else:
                            print ("Unexpected error when creating token")
                            sys.exit(1)
                    if su.is_user_alredy_exists():
                        print ("User alredy exists! Use sync command to modify it.")
                        sys.exit(1)
                    if generate_creds:
                        username =  su.path_username
                        password =  self._random_string_generator(int(self.parsed_config["generated_pass_length"]))
                        secret = self.creds_to_secret(username, password)
                        custom_secrets.append(secret)
                        if generate_hash:
                            hashes = self.generate_hashes(password, username)
                            custom_secrets.append(hashes)
                    if generate_hash and not generate_creds:
                        print ("User had no creds! Hashes are generated from it (at the moment). Ignoring this option")
                    if append_secret:
                        if self.eval_secrets_from_input(append_secret):
                            custom_secrets += self.eval_secrets_from_input(append_secret)
                        else:
                            print ("Unexpected input at append section.")
                    if custom_secrets:
                        if su.sync_user(path, secrets=custom_secrets, replace=replace):
                            print ("Done")
                            sys.exit(0)
                        else:
                            print ("Error occured when creating user")
                            sys.exit(1)
                    else:
                        print ("You cant create user without any creds, it does not make sense!")
                        print ("You may use --gen_creds option, or --append_secret")
                        sys.exit(1)

                if item == "delete":
                    if create_type == "token":
                        if self.is_token_exists_by_name(user):
                            if self.delete_token_by_name(user):
                                print ("Done")
                                sys.exit(0)
                            else:
                                print ("Cant delete token")
                                sys.exit(1)
                        else:
                            print ("No such token")
                            sys.exit(1)
                    if su.is_user_alredy_exists():
                        if su.delete_myself():
                            print ("Done")
                            sys.exit(0)
                        else:
                            print ("Error occured when deleting user")
                            sys.exit(1)
                    else:
                        print ("No such user")
                        sys.exit(1)

                if item == "sync":
                    if su.is_user_alredy_exists():
                        if regen_creds:
                            if su.vault.check_delete_secret(su.path_till_user+self.parsed_config["creds_containing_secret"]):
                                username =  su.path_username
                                password =  self._random_string_generator(int(self.parsed_config["generated_pass_length"]))
                                secret = self.creds_to_secret(username, password)
                                custom_secrets.append(secret)
                            else:
                                print ("Unexpected error when deleting old {}".format(self.parsed_config["creds_containing_secret"]))
                                sys.exit(1)
                        if generate_hash and regen_creds:
                            hashes = self.generate_hashes(password, username)
                            custom_secrets.append(hashes)
                        elif generate_hash and not regen_creds:
                            creds = self.get_creds(su)
                            if creds.get("password") and creds.get("username"):
                                hashes = self.generate_hashes(creds["password"], ["username"])
                                custom_secrets.append(hashes)
                            else:
                                print ("hashes can not be (re)generated, user have no creds, and flag --(re)gen_creds is not set")
                                sys.exit(1)
                        if append_secret:
                            if self.eval_secrets_from_input(append_secret):
                                custom_secrets += self.eval_secrets_from_input(append_secret)
                        if su.sync_user(path, secrets=custom_secrets, strict=strict, replace=replace):
                            print ("Done")
                            sys.exit(0)
                        else:
                            print ("Error occured when syncing")
                            sys.exit(1)
                    else:
                        print ("No such user. You may use create command.")
                        sys.exit(1)

                if item == "apply":
                    print ("Logic not implemented yet. Go away =))")
                    sys.exit(1)
                


    def eval_secrets_from_input(self, data):
        ret = []
        helps = """
Unexpected secret format. Please use this:
   --append_secret '[{"secret1":{"data":{"k":"v"}}},{"secret2":{"data":{"k":"v"}}}]'
Or this:
   --append_secret '{"secret2":{"data":{"k":"v"}}}'

Ignoring this secret.
"""

        if data[:1] == "[" and data[-1:] == "]":
            for secret in data:
                try:
                    data = data[1:-1].split(",")
                    for item in data:
                        ret.append(ast.literal_eval(item))
                except Exception as error:
                    print ("Cant parse given secrets: {}".format(error.args))
                    print (helps)
                    return []
                return ret
                if type(data) == dict:
                    ret.append(data)
                else:
                    return False
        #No. We got only one {secret}.
        elif data[:1] == "{" and data[-3:] == "}"*3:
            try:
                data = ast.literal_eval(data)
            except Exception as error:
                print ("Cant parse given secret: {}".format(error.args))
                print (helps)
                return []
            if type(data) == dict:
                ret.append(data)
        else:
            print (helps)
            return False

        return ret

    def generate_hashes(self, password, username):
        postgres_md5 = hashlib.md5(password.encode('UTF-8')+username.encode('UTF-8')).hexdigest()
        pass_sha256 = hashlib.sha256(password.encode('UTF-8')).hexdigest()
        return ({"hashes":{"data":{"postgres_md5":postgres_md5, "pass_sha256":pass_sha256}}})


    def creds_to_secret(self,username, password):
        return({self.parsed_config["creds_containing_secret"]:
                                {"data":
                                {self.parsed_config["password_containing_value"]:password,
                                 self.parsed_config["username_containing_value"]:username}}})

    def _random_string_generator(self,N):
        """small internal to securely generate N dights string """
        return ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(N))

    def _safeget(self,dct, keys):
        for key in keys:
            try:
                dct = dct[key]
            except Exception:
                return None
        return dct

    def get_creds(self, su:vault_service_user):
        rez = {"username":False, "password":False}
        for secret in su.vault_secrets:
            username = self._safeget(secret, [self.parsed_config["creds_containing_secret"], "data", self.parsed_config["username_containing_value"]])
            password = self._safeget(secret, [self.parsed_config["creds_containing_secret"], "data", self.parsed_config["password_containing_value"]])
            if username:
                rez.update({"username":username})
            if password:
                rez.update({"password":password})
        return rez

    def issue_token(self, name, policies, ttl, num_uses):
        payload = self.vault.token_payload_generator(name,num_uses,policies,ttl)
        token = self.vault.create_token(payload)
        if token:
            return token
        else:
            return False

    def delete_token_by_name(self, name, delete_multiple=False):

        #display name is not uniq identificator, so there is a flag delete_multiple
        accs = self.vault.token_name_to_accessors(name, False)
        if accs and len(accs) == 1:
            self.vault.check_delete_token(accs[0])
            return True
        elif accs and len(accs) > 1:
            if delete_multiple:
                for acc in accs:
                    self.vault.check_delete_token(acc)
                return True
            else:
                print ("Multiple tokens witch such name, and flag delete_multiple is not set")
        else:
            print ("No such token")
            return False

    def is_token_exists_by_name(self, name):
        accs = self.vault.token_name_to_accessors(name, False)
        if accs:
            return True
        else:
            return False






if __name__ == '__main__':
    hashish()
