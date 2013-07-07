#!/usr/bin/env python

import optparse
import pickle
import os.path
import hashlib
import re

def md5sum(filename, verbosity):
  md5 = hashlib.md5()
  with open(filename,'rb') as f: 
    for chunk in iter(lambda: f.read(128*md5.block_size), b''): 
      md5.update(chunk)
    return md5.hexdigest()

def locatefiles(user, domain=null):
  base = '/usr/local/apache/domlogs/'
  if domain:
    if os.path.exists(base + domain):
      return [base + domain]
    else:
      userdata = open('/var/cpanel/userdata/' + user + '/main', 'r').readlines()
      for line in userdata:
        if re.search('^\s\s' + domain + ':', line):
           subdom = line.split(':')[1].strip().split('\n')[0]
           break
       if os.path.exists(base + subdom):
         return [base + subdom]
  if user:
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
            # Parse line
            


def main():
  """Determine requested options and route functions to be executed."""

  command = optparse.OptionParser(description='ReportUserAgent, or rua performs various functions and mediates display of collected user-agent data from a domain\'s access logs or for the entirety of a user.', prog='rua', version='rua 0.1', usage='%prog [-v] [-d domain] [-u user] [-f filename]')
  command.add_option('-u', '--user', action='store', dest='user', help='Calculates report for the specified user. (Otherwise, a domain or cwd is resolved.).')
  command.add_option('-d', '--domain', action='store', dest='domain', help='Calculates report for the specified domain. (Otherwise, a user or cwd is resolved.).')
  command.add_option('-v', '--verbose', action='store_true',help='Enables verbose logging output.')
  command.add_option('-f', '--file', action='store', dest='file', help='Provide a specific log file to read.')

  options, arguments = command.parse_args()
  if options.file:
    if os.path.exists(options.file):
      md5 = md5sum(options.file, options.verbose)
    else:
      print "\n[!] \'%s\' does not appear to be a file. Please confirm it\'s validity.\n" % options.file
      command.print_help()
  elif options.domain:
    if os.path.exists('/etc/userdomains'):
      userdomains = open('/etc/userdomains', 'r').readlines()
      for line in userdomains:
        if re.search('^' + options.domain + '\:' , line):
          user = line.split(':')[1].strip().split('\n')[0]
          break
      if 'user' in locals():
        
      else:
        print '\n[!] Domain `%s` wasn\'t found in /etc/userdomains.\n' % options.domain
    else:
      print "\n[!] /etc/userdomains doesn't exist. Is this a cPanel server?\n"
      command.print_help()
  elif options.user:
    if os.path.exists('/var/cpanel/userdata/' + options.user + '/main'):
     userdata = open('/var/cpanel/userdata/' + options.user + '/main').readlines()
     for line in userdata:
       if re.search('^main_domain:', line):
         pdomain = line.split(':')[1].strip().split('\n')[0]
         break
     if 'pdomain' in locals():
     else:
      print '\n[!] Primary domain not found for User `%s`!' % options.user 
      command.print_help()
  else:
    command.print_help()

if __name__ == '__main__':
  main()
