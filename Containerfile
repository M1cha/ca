FROM docker.io/archlinux:latest

RUN pacman -Syu --noconfirm \
	ansible \
	libp11 \
	opensc \
	pcsc-tools \
	openssh
