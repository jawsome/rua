#!/usr/bin/env python

import optparse
import pickle
import os.path
import hashlib
import re

def log(level, message, object):
  if level == 'verbose' & object['verbose']:
    print '[-] %s ' % message
  elif level == 'error':
    print '\n\033[1;31m[!] %s \033[0m\n' % message

def md5sum(file):
  md5 = hashlib.md5()
  with open(file,'rb') as f: 
    for chunk in iter(lambda: f.read(128*md5.block_size), b''): 
      md5.update(chunk)
    return md5.hexdigest()

def locatefiles(data):
  base = '/usr/local/apache/domlogs/'
  if len(data['domain']) == 1:
    domain = data['domain']
    data['domain'][domain]['files'] = []
    if os.path.exists(base + domain):
      data['domain']['files'].append([base + domain])
    else:
      userdata = open('/var/cpanel/userdata/' + data['user'] + '/main', 'r').readlines()
      for line in userdata:
        if re.search('^\s\s' + domain + ':', line):
           subdom = line.split(':')[1].strip().split('\n')[0]
           if data['domain'][subdom] not in locals():
             data['domain'][subdom] = {}
             data['domain'][subdom]['files'] = []
           data['domain'][subdom]['files'].append([subdom])
      for file in data['domain'][subdom]['files']:
        if os.path.exists(dom[0]):
          dom.append(md5sum(dom0))
  elif len(data['domain']) > 1:
    userlogdir = base + user
    if os.path.exists(userlogdir):
      domains = []
      userdomain = open('/etc/userdomains', 'r').readlines()
      for line in userdomain:
        if re.search(':' + user + '\n$', line):
          match = line.split(':').strip()[0]
          if os.path.exists(userlogdir + match):
             domains.append(userlogdir + match)
      return domains
    else:
      print "\n[!] `%s`'s domlog directory doesn't exist. Stopping here.\n"

def parsefiles(files):
  if type(files) is list:
    for file in files:
      if os.path.exists(file):
        try:
          curr = open(file, r).readlines()
          for line in curr:
            print line
            #Do things with lines.
        except:
          pass        


def main():
  """Determine requested options and route functions to be executed."""

  command = optparse.OptionParser(description='ReportUserAgent, or rua performs various functions and mediates display of collected user-agent data from a domain\'s access logs or for the entirety of a user.', prog='rua', version='rua 0.1', usage='%prog [-v] [-d domain] [-u user] [-f filename]')
  command.add_option('-u', '--user', action='store', dest='user', help='Calculates report for the specified user. (Otherwise, a domain or cwd is resolved.).')
  command.add_option('-d', '--domain', action='store', dest='domain', help='Calculates report for the specified domain. (Otherwise, a user or cwd is resolved.).')
  command.add_option('-v', '--verbose', action='store_true',help='Enables verbose logging output.')
  command.add_option('-f', '--file', action='store', dest='file', help='Provide a specific log file to read.')

  options, arguments = command.parse_args()
  data = {}
  data['files'] = []
  data['domains'] = {}
  if options.verbose:
    data['verbose'] = true
  if options.file:
    log('verbose', 'File provided, checking to see if it exists.', data)
    if os.path.exists(options.file):
      log('verbose', 'File exists, generating md5...')
      filedata = [options.file,md5sum(options.file)]
      log('verbose', 'Generated: ' + filedata, data)
      data['files'].append(filedata)
      print data
    else:
      log('error', "'%s' does not appear to be a file. Please confirm it's validity." % options.file, data)
      command.print_help()
  elif options.domain:
    log('verbose', 'Domain provided, checking to see if it\'s in /etc/userdomains.', data)
    if os.path.exists('/etc/userdomains'):
      userdomains = open('/etc/userdomains', 'r').readlines()
      for line in userdomains:
        if re.search('^' + options.domain + '\:' , line):
          log('verbose', 'Domain found in /etc/userdomains!', data)
          data['user'] = line.split(':')[1].strip().split('\n')[0]
      if data['user'] in locals():
        locatefiles(data)
      else:
        log('error', "Domain `%s` wasn't found in /etc/userdomains." % options.domain, data)
    else:
      log('error', "/etc/userdomains doesn't exist. Is this a cPanel server?", data)
      command.print_help()
  elif options.user:
    log('verbose', 'User provided, checking for userdata file.', data)
    if os.path.exists('/var/cpanel/userdata/' + options.user + '/main'):
      log('verbose', 'Userdata exists, checking for /etc/passwd.', data)
      if os.path.exists('/etc/passwd'):
        log('verbose', '/etc/passwd exists, checking for user in passwd', data)
        passwd = open('/etc/passwd', 'r').readlines()
        for line in passwd:
          if re.search('^' + options.user + ':', line):
            log('verbose', 'User found!\n\t %s' % line, data)
            data['user'] = options.user
        if os.path.exists('/etc/userdomains'):
          log('verbose', 'Loading domains from /etc/userdomains for `%s`...' % options.user, data)
          userdomains = open('/etc/userdomains', 'r').readlines()
          for line in userdomains:
            if re.search('^(.*)\:' + options.user , line):
              data['domain'][line.strip().split(":")[0].strip()] = {}
          locatefiles(data)
        else:
          log('error', "/etc/userdomains doesn't exist. Is this a cPanel server?", data)
          command.print_help()
      else:
        log('error', "/etc/passwd doesn't exist. Exiting...", data)
        command.print_help()
    else:
      log('error', "No userdata file for `%s`!" % options.user, data)
      command.print_help()


if __name__ == '__main__':
  main()
