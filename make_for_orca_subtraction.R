rm(list = ls())

args = commandArgs(trailingOnly = T)
if (is.na(args[1])) {
   cat("WARNING - no config file specified, using default\n")
   source("conf.R")
   orca_conf="orca_conf"
} else {
  conf_name=args[1]
  if (any(grep("*\\.R$",conf_name,ignore.case=T))){
    conf_name=sub("(*)\\.R$","\\1",conf_name)
}
source(paste0(conf_name,".R"))
orca_conf=paste0("orca_",conf_name,"")
}
source("shared.R")
#make config for orca
write(get_orca_dir(),file=paste0(orca_conf))

dfile=get_dfile()
susi_sources_name=get_susi_sources()
orca_dir=paste0(get_orca_dir(),"/pre/")

dir.create(orca_dir,recursive=TRUE)
print(orca_dir)

orca_col_type = "continuous."
fields_file = paste0(orca_dir,'#.fields')

make_for_cluster<-function(data,cl,susi)
{
    meta_col_id = c(grep("^name", names(data)))
    features_id = get_features_id(data)
    cluster_set = data
    data_result = cluster_set[,c(meta_col_id, features_id)]
    data_res_file  = gsub("#.fields", paste0(cl, ".data"),fields_file)    
    write.table(data_result, file = data_res_file, quote = F, row.names = F, col.names = F, sep=",")
    #should eliminate '.' from field names
    meta_col = sapply(names(cluster_set)[meta_col_id], function(x)paste0(gsub('[\\.: ,]', '_', x),':','ignore.'))
    features_col = sapply(names(cluster_set)[features_id], function(x)paste0(gsub('[\\.: ,]', '_', x),':',orca_col_type))# column names
    fields_result = c(meta_col, features_col)
    fields_res_file  = gsub("#",cl,fields_file)    
    write.table(fields_result, file = fields_res_file, quote = F, row.names = F, col.names = F)
}#end make_
trim<-function(x) gsub("^\\s+|\\s+$","",x)

if (loadRDS){
    susi_sources = readRDS(file=to_rds(susi_sources_name))
    data = readRDS(file=to_rds(dfile))
}else{
    susi_sources = read.csv(file=susi_sources_name, head=F, sep=";")
    data = read.csv(file=dfile, head=T, sep=";",check.names=F)
}

cat("file name:",dfile,"\n")
cat("data size",dim(data),"\n")
cat("malic: ",nrow(data[data$malicious==1,]),"benign: ",nrow(data[data$malicious==0,]),"\n")
names(susi_sources)<-c("name","s")
sources_list=unique(susi_sources$s)
gdata=list()#for future use
if (noSUSI){
    sources_list=c('ALL')   
}

feature_selection_time <- 0

for(source in sources_list){
#source <- "NETWORK_INFORMATION"
    per_source = susi_sources[susi_sources$s == source,]
    if (noSUSI){
        gdata[[source]]=data
    }else{
        gdata[[source]]=data[data$name %in% per_source$name,]
    }
    cldata=gdata[[source]]
    malicious = cldata[cldata$malicious==1,]
    benign = cldata[cldata$malicious==0,]
    cat(source," ",nrow(cldata), " b:", nrow(benign)," m:",nrow(malicious),"\n")

start <- Sys.time()
if(nrow(benign)>minSamples && nrow(malicious) > 0)
{

mdata <- cldata
 
malware = mdata[mdata$malicious == 1,]
benign = mdata[mdata$malicious == 0,]

benign_sum <- list()

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
write.table(as.data.frame(unlist(flow_sub_log_set)),paste0("category/",source,"_number.csv"),col.names=F,row.names=F)
cldata <- cldata[c(1,as.integer(flow_sub_log_set),ncol(mdata))]
#break
}

end <- Sys.time()
consume <- end -start
feature_selection_time <- feature_selection_time + end - start


    malicious = cldata[cldata$malicious==1,]
    benign = cldata[cldata$malicious==0,]

    trainset=benign
    testset=cldata
    cat(source," train:", nrow(trainset)," test:",nrow(testset),"\n")
    if (nrow(benign)>minSamples){
        make_for_cluster(trainset, paste0(source,"_train"),source)
        make_for_cluster(testset, paste0(source,"_test"),source)
    }
}
print(feature_selection_time)
