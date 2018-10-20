#!/bin/bash
  #Este é um comentário
  #Este é outro comentário
	make
	sudo insmod cryptomodule.ko
	sudo ./usuario c teste
	sudo ./usuario d teste
    dmesg
	sudo rmmod cryptomodule.ko
