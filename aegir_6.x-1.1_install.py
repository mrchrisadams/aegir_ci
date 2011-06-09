#! /usr/bin/env python
#
# Libcloud tool to build Rackspace VPS, install Aegir and build makefile-based Drupal projects
# Designed for use as a Jenkins project, works from CLI just fine though
# Dependencies: libcloud, fabric
#
# Written by Miguel Jacq (mig5) of Green Bee Digital and the Aegir project
# http://greenbeedigital.com.au
#

from libcloud.compute.types import Provider
from libcloud.compute.providers import get_driver
from libcloud.compute.ssh import SSHClient, ParamikoSSHClient
import libcloud.security
import os, sys, string, ConfigParser, socket, time, random, traceback
import fabric.api as fabric

libcloud.security.VERIFY_SSL_CERT = True

# Fetch some values from the config file
config = ConfigParser.RawConfigParser()
config.read(os.path.expanduser("~/aegir_ci/aegir_ci_config.ini"))

# Try to abstract the provider here, as we may end up supporting others
# Theoretically since we are using libcloud, it should support any
# provider that supports the deploy_node function (Amazon EC2 doesn't)
provider = config.get('Aegir', 'provider')
provider_driver = config.get(provider, 'driver')

# API credentials
user = config.get(provider, 'user')
key = config.get(provider, 'key')

# Preferred image and size
config_distro = config.get(provider, 'distro')
config_size = config.get(provider, 'size')

# These are used as options to Aegir during install
email = config.get('Aegir', 'email')
# A trusted IP to grant access to in the firewall
trusted_ip = config.get('Aegir', 'trusted_ip')
# Where our build files are
builds_repo = config.get('Aegir', 'builds_repo')

hostname = 'aegirjenkins-%d' % random.randrange(0, 10001, 2)

# Some basic dependency tests for this job itself
def dependency_check():
        try:   
                import fabric                                   

        except ImportError:
                print "You need Fabric installed (apt-get install fabric)"
                sys.exit(1)

# Helper script to generate a random password
def gen_passwd():
        N=8
        return ''.join(random.choice(string.ascii_letters + string.digits) for x in range(N))

# Install dependencies for Aegir
def fab_install_dependencies(newpass):
	fabric.run("apt-get update", pty=True)
        fabric.run("echo 'postfix postfix/main_mailer_type select Internet Site' | debconf-set-selections", pty=True)
        fabric.run("echo 'postfix postfix/mailname string $HOSTNAME' | debconf-set-selections", pty=True)
        fabric.run("echo 'postfix postfix/destinations string localhost.localdomain, localhost' | debconf-set-selections", pty=True)
        fabric.run("echo mysql-server mysql-server/root_password select %s | debconf-set-selections" % newpass, pty=True)
        fabric.run("echo mysql-server mysql-server/root_password_again select %s | debconf-set-selections" % newpass, pty=True)
        fabric.run("apt-get -y install apache2 php5 php5-cli php5-gd php5-mysql postfix mysql-server sudo rsync git-core unzip", pty=True)

# Prepare a basic firewall
def fab_prepare_firewall():
        print "===> Setting a little firewall"
        fabric.run("iptables -I INPUT -s %s -p tcp --dport 22 -j ACCEPT; iptables -I INPUT -s %s -p tcp --dport 80 -j ACCEPT; iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT; iptables --policy INPUT DROP" % (trusted_ip, trusted_ip), pty=True)

# Fabric command to set some Apache requirements
def fab_prepare_apache():
        print "===> Preparing Apache"
        fabric.run("a2enmod rewrite", pty=True)
        fabric.run("ln -s /var/aegir/config/apache.conf /etc/apache2/conf.d/aegir.conf", pty=True)

# Fabric command to raise PHP CLI memory limit (for Drupal 7 / OpenAtrum)
def fab_prepare_php():
	print "===> Preparing PHP"
	fabric.run("sed -i s/'memory_limit = 32M'/'memory_limit = 256M'/ /etc/php5/cli/php.ini", pty=True)

# Fabric command to add the aegir user and to sudoers also
def fab_prepare_user():
        print "===> Preparing the Aegir user"
        fabric.run("useradd -r -U -d /var/aegir -m -G www-data aegir", pty=True)
        fabric.run("echo 'aegir ALL=NOPASSWD: /usr/sbin/apache2ctl' >> /etc/sudoers", pty=True)

# Fabric command to fetch Drush
def fab_fetch_drush():
        print "===> Fetching Drush"
        fabric.run("su - -s /bin/sh aegir -c'wget http://ftp.drupal.org/files/projects/drush-7.x-4.4.tar.gz'", pty=True)
        fabric.run("su - -s /bin/sh aegir -c' gunzip -c drush-7.x-4.4.tar.gz | tar -xf - '", pty=True)
        fabric.run("su - -s /bin/sh aegir -c 'rm /var/aegir/drush-7.x-4.4.tar.gz'", pty=True)

# Fabric command to fetch Provision
def fab_fetch_provision():
        print "===> Fetching Provision"
        fabric.run("su - -s /bin/sh aegir -c 'php /var/aegir/drush/drush.php dl -y --destination=/var/aegir/.drush provision-6.x-1.1'", pty=True)

# Fabric command to run the install.sh aegir script
def fab_hostmaster_install(domain, email, newpass):
        print "===> Running hostmaster-install"
        fabric.run("su - -s /bin/sh aegir -c 'php /var/aegir/drush/drush.php hostmaster-install %s --client_email=%s --aegir_db_pass=%s --yes'" % (domain, email, newpass), pty=True)
        fabric.run("su - -s /bin/sh aegir -c 'php /var/aegir/drush/drush.php -y @hostmaster vset hosting_queue_tasks_frequency 1'", pty=True)
        fab_run_dispatch()

# Download, import and verify platforms
def fab_install_platform(platform_name):
        fabric.run("su - -s /bin/sh aegir -c 'php /var/aegir/drush/drush.php make %s/%s.build /var/aegir/platforms/%s'" % (builds_repo, platform_name, platform_name), pty=True)
        fabric.run("su - -s /bin/sh aegir -c 'php /var/aegir/drush/drush.php --root=\'/var/aegir/platforms/%s\' provision-save \'@platform_%s\' --context_type=\'platform\''" % (platform_name, platform_name), pty=True)
        fabric.run("su - -s /bin/sh aegir -c 'php /var/aegir/drush/drush.php @hostmaster hosting-import \'@platform_%s\''" % platform_name, pty=True)
        fab_run_dispatch()

# Install a site
def fab_install_site(platform_name, profile):
        fabric.run("su - -s /bin/sh aegir -c '/var/aegir/drush/drush.php --uri=\'%s.mig5.net\' provision-save \'@%s.mig5.net\' --context_type=\'site\' --platform=\'@platform_%s\' --profile=\'%s\' --db_server=\'@server_localhost\''" % (platform_name, platform_name, platform_name, profile), pty=True)
        fabric.run("su - -s /bin/sh aegir -c '/var/aegir/drush/drush.php @%s.mig5.net provision-install'" % platform_name, pty=True)
        fabric.run("su - -s /bin/sh aegir -c '/var/aegir/drush/drush.php @hostmaster hosting-task @platform_%s verify'" % platform_name, pty=True)
        fab_run_dispatch()

# Force the dispatcher
def fab_run_dispatch():
        fabric.run("su - -s /bin/sh aegir -c 'php /var/aegir/drush/drush.php @hostmaster hosting-dispatch'", pty=True)

def run_platform_tests():
        print "===> Installing some common platforms"
        fab_install_platform('drupal6')
        fab_install_platform('drupal7')
        fab_install_platform('openatrium')

def run_site_tests():
        print "===> Installing some sites"
        fab_install_site('drupal6', 'default')
        fab_install_site('drupal7', 'standard')
        fab_install_site('openatrium', 'openatrium')

def main():
        # Run some tests
        dependency_check()

	# Set a random password for the MySQL root user.
	newpass = gen_passwd()

        # Make a new connection
        Driver = get_driver( getattr(Provider, provider_driver) )
        conn = Driver(user, key)

        # Get a list of the available images and sizes
        images = conn.list_images()
        sizes = conn.list_sizes()

        # We'll use the distro and size from the config ini
        preferred_image = [image for image in images if config_distro in image.name]
        assert len(preferred_image) == 1, "We found more than one image for %s, will be assuming the first one" % config_distro

        preferred_size = [size for size in sizes if config_size in size.name]

        # Create and deploy a new server now, and run the deployment steps defined above
        print "Provisioning server and running deployment processes"
        try:
		node = conn.create_node(name=hostname, image=preferred_image[0], size=preferred_size[0])
        except:
		print "Error provisioning new node"
		e = traceback.print_exc()
                raise SystemExit(e)

        print "Provisioning complete, you can ssh as root to %s" % node.public_ip[0]
        if node.extra.get('password'):
                print "The root user's password is %s" % node.extra.get('password')
		password = node.extra.get('password')
	

        # VPS aren't immediately available after provisioning sometimes
        # Let's try and loop until the node state is 'Running'.

        var = 1
        while var == 1:
                nodes = conn.list_nodes()
                for node in nodes: 
                        if hostname in node.name:
                                if node.state == 0:
				        # Setting some parameters for fabric
				        domain = socket.getfqdn(node.public_ip[0])
				        fabric.env.host_string = domain
				        fabric.env.user = 'root'
				        fabric.env.password = password

				        try:
				                fab_prepare_firewall()
				                fab_install_dependencies(newpass)
				                fab_prepare_apache()
				                fab_prepare_php()
				                fab_prepare_user()
				                fab_fetch_drush()
				                fab_fetch_provision()
				                fab_hostmaster_install(domain, email, newpass)
				                run_platform_tests()
				                run_site_tests()

					        print "===> Destroying this node"
					        conn.destroy_node(node)

				        except:
				                e = traceback.print_exc()
				                raise SystemExit(e)

                                        var = 2
                                        break
                                else:
                                        print "New host doesn't seem booted yet. Sleeping and will try again in 20 secs..."
                                        time.sleep(20)
                                        continue


if __name__ == "__main__":
        main()
