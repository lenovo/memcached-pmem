Copyright and License
-----------

Copyright 2018 Lenovo

Licensed under the BSD-3 license. see LICENSE.Lenovo.txt for full text

Description
-----------

This project provides a sample of persistent memory support in memcached. It enables memcached to use persistent memory for data caching. For more information on memcached and persistent memory, visit http://www.memcached.org and http://pmem.io

Installing
-----------

* To install memcached with persistent memory support:

  1. Clone the project

  2. 'cd' to the directory where the project is cloned and invoke the 'configure' scripts:

.. code-block:: console

       ./configure --enable-pslab

  3. Invoke the 'make' program:

.. code-block:: console

       make

  4. If 'make' succeeds, you can install the program:

.. code-block:: console

       make install

Requirements
-----------

Besides the libraries depended on by memcached, persistent memory enhancement needs the Persistent Memory Development Kit (PMDK) to build. PMDK is available from https://github.com/pmem/pmdk


Usage
-----------

Start memcached with persistent memory
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Assuming that the persistent memory device is '/dev/pmem0', format it with ext4 file system type:

.. code-block:: console

   mkfs -t ext4 /dev/pmem0

Then mount it in dax mode:

.. code-block:: console

   mount -o dax /dev/pmem0 /mnt/pmfs

Finnaly start memcached:

.. code-block:: console

   memcached -u root -o pslab_file=/mnt/pmfs/pool,pslab_force

To use persistent memory caching all the data:

.. code-block:: console

   memcached -u root -m 0 -o pslab_file=/mnt/pmfs/pool,pslab_force

Restart memcached with data recovery
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
With persistent memory support enabled, memcached can recover the data stored in persistent memory back from abrupt termination caused by system panic or application crash.

.. code-block:: console

   memcached -u root -o pslab_file=/mnt/pmfs/pool,pslab_force,pslab_recover
