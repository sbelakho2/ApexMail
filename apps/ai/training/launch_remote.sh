#!/bin/bash
cd ~/ApexMail/apps/ai/training
rm -rf output_agent
nohup bash train_agent.sh > output_agent_log.txt 2>&1 &
echo "LAUNCHED PID=$!"
sleep 3
ps aux | grep torchrun | grep -v grep | wc -l
