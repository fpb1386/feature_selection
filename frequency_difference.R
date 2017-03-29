start <- Sys.time()
# mdata: pre-category malware and benign apps
 
malware = mdata[mdata$malicious == 1,]
benign = mdata[mdata$malicious == 0,]

benign_sum <- list()
if(nrow(benign)>5 && nrow(malware) > 0)
{

for(i in 2:(ncol(mdata)-1))
{
  benign_sum <- cbind(benign_sum,sum(benign[,i])/nrow(benign))
}

malware_sum <- list()

for(i in 2:(ncol(mdata)-1))
{
  malware_sum <- cbind(malware_sum,sum(malware[,i])/nrow(malware))
}

flow_sub_diff <- list()


for(i in 1:length(benign_sum))
{
  subtraction <- as.double( as.double(malware_sum[i]) - as.double(benign_sum[i]) )
  flow_sub_diff <- cbind(flow_sub_diff,subtraction)
}

flow_sub_log_set <- list()

for(i in 1:length(benign_sum))
{
  if( as.double(flow_sub_diff[i]) > 0.08 || as.double(flow_sub_diff[i]) < -0.08 )
  {
    flow_sub_log_set <- cbind(flow_sub_log_set,as.integer(i+1))
  }
}
cat("size:",length(flow_sub_log_set),"\n")
critical_data_flows <- as.data.frame(unlist(flow_sub_log_set)) #pre-category critical data flows
cldata <- cldata[c(1,as.integer(flow_sub_log_set),ncol(mdata))] #pre-category benign apps and malware with critical data flows
}
print(feature_selection_time) #CPU consumption time for this feature selection process
