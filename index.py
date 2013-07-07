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
        print 'User `%s` found!' % user
      else:
        print 'User not found for domain: `%s`' % options.domain
    else:
      print "Error"
  elif options.user:
    if os.path.exists('/var/cpanel/userdata/' + options.user + '/main'):
     userdata = open('/var/cpanel/userdata/' + options.user + '/main').readlines()
     for line in userdata:
       if re.search('^main_domain:', line):
         pdomain = line.split(':')[1].strip().split('\n')[0]
         break
     if 'pdomain' in locals():
      print 'Primary domain `%s` found for User `%s`' % (pdomain,options.user)
     else:
      print 'Primary domain not found for User `%s`' % options.user 
  else:
    command.print_help()

if __name__ == '__main__':
  main()
