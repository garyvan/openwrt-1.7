#!/bin/sh
echo $1 > /proc/irq/$2/smp_affinity
