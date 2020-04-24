package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchevents"
	"github.com/aws/aws-sdk-go/service/ecs"
	"os"
	"strconv"
	"strings"
	"time"
)

type Plugin struct {
	Key                     string
	Secret                  string
	Region                  string
	Family                  string
	TaskRoleArn             string
	Service                 string
	ContainerName           string
	DockerImage             string
	Tag                     string
	Cluster                 string
	LogDriver               string
	LogOptions              []string
	DeploymentConfiguration string
	PortMappings            []string
	Environment             []string
	SecretEnvironment       []string
	Labels                  []string
	EntryPoint              []string
	DesiredCount            int64
	CPU                     int64
	Memory                  int64
	MemoryReservation       int64
	NetworkMode             string
	YamlVerified            bool
	TaskCPU                 string
	TaskMemory              string
	TaskExecutionRoleArn    string
	Compatibilities         string
	HealthCheckCommand      []string
	HealthCheckInterval     int64
	HealthCheckRetries      int64
	HealthCheckStartPeriod  int64
	HealthCheckTimeout      int64
	Ulimits                 []string
	MountPoints             []string
	Volumes                 []string

	// ServiceNetworkAssignPublicIP - Whether the task's elastic network interface receives a public IP address. The default value is DISABLED.
	ServiceNetworkAssignPublicIp string

	// ServiceNetworkSecurityGroups represents the VPC security groups to use
	// when running awsvpc network mode.
	ServiceNetworkSecurityGroups []string

	// ServiceNetworkSubnets represents the VPC security groups to use when
	// running awsvpc network mode.
	ServiceNetworkSubnets []string

	TaskDefinitionTags []string

	TaskTags       []string
	ScheduledTasks string
}

// https://docs.aws.amazon.com/sdk-for-go/api/service/cloudwatchevents/#PutRuleInput
type CloudWatchEventRule struct {
	Description string `json:"description"`
	Name        string `json:"name"`
	//EventBusName string `json:"event_bus"`
	//RoleArn string `json:"role_arn"`
	//Tags []string `json:tags`
	ScheduledExpression string `json:"scheduled_expression"`
}

// https://docs.aws.amazon.com/sdk-for-go/api/service/cloudwatchevents/#Target
type CloudWatchEventTarget struct {
	Id                    string   `json:"id"`
	ClusterArn            string   `json:"cluster_arn"`
	Input                 string   `json:"input"`
	LaunchType            string   `json:"launch_type"`
	NetworkSecurityGroups []string `json:"network_security_groups"`
	NetworkSubnets        []string `json:"network_subnets"`
	RoleArn               string   `json:"role_arn"`
	TaskCount             int64    `json:"task_count"`
	PlatformVersion       string   `json:"platform_version"`
	Group                 string   `json:"group"`
	NetworkAssignPublicIP string   `json:"network_assign_public_ip"`
}

// https://docs.aws.amazon.com/sdk-for-go/api/service/cloudwatchevents/#PutTargetsInput
type CloudWatchEventRuleAndTargets struct {
	Rule    CloudWatchEventRule     `json:rule`
	Targets []CloudWatchEventTarget `json:targets`
}

const (
	softLimitBaseParseErr             = "error parsing ulimits softLimit: "
	hardLimitBaseParseErr             = "error parsing ulimits hardLimit: "
	hostPortBaseParseErr              = "error parsing port_mappings hostPort: "
	containerBaseParseErr             = "error parsing port_mappings containerPort: "
	minimumHealthyPercentBaseParseErr = "error parsing deployment_configuration minimumHealthyPercent: "
	maximumPercentBaseParseErr        = "error parsing deployment_configuration maximumPercent: "
	readOnlyBoolBaseParseErr          = "error parsing mount_points readOnly: "
)

func (p *Plugin) Exec() error {
	fmt.Println("Drone AWS ECS Plugin built")
	awsConfig := aws.Config{}

	if len(p.Key) != 0 && len(p.Secret) != 0 {
		awsConfig.Credentials = credentials.NewStaticCredentials(p.Key, p.Secret, "")
	}
	awsConfig.Region = aws.String(p.Region)
	svc := ecs.New(session.New(&awsConfig))

	Image := p.DockerImage + ":" + p.Tag
	if len(p.ContainerName) == 0 {
		p.ContainerName = p.Family + "-container"
	}

	definition := ecs.ContainerDefinition{
		Command: []*string{},

		DnsSearchDomains:      []*string{},
		DnsServers:            []*string{},
		DockerLabels:          map[string]*string{},
		DockerSecurityOptions: []*string{},
		EntryPoint:            []*string{},
		Environment:           []*ecs.KeyValuePair{},
		Essential:             aws.Bool(true),
		ExtraHosts:            []*ecs.HostEntry{},

		Image:        aws.String(Image),
		Links:        []*string{},
		MountPoints:  []*ecs.MountPoint{},
		Name:         aws.String(p.ContainerName),
		PortMappings: []*ecs.PortMapping{},

		Ulimits: []*ecs.Ulimit{},
		//User: aws.String("String"),
		VolumesFrom: []*ecs.VolumeFrom{},
		//WorkingDirectory: aws.String("String"),
	}
	volumes := []*ecs.Volume{}
	if p.CPU != 0 {
		definition.Cpu = aws.Int64(p.CPU)
	}

	if p.Memory == 0 && p.MemoryReservation == 0 {
		definition.MemoryReservation = aws.Int64(128)
	} else {
		if p.Memory != 0 {
			definition.Memory = aws.Int64(p.Memory)
		}
		if p.MemoryReservation != 0 {
			definition.MemoryReservation = aws.Int64(p.MemoryReservation)
		}
	}

	// Volumes
	for _, volume := range p.Volumes {
		cleanedVolume := strings.Trim(volume, " ")
		parts := strings.SplitN(cleanedVolume, " ", 2)
		vol := ecs.Volume{
			Name: aws.String(parts[0]),
		}
		if len(parts) == 2 {
			vol.Host = &ecs.HostVolumeProperties{
				SourcePath: aws.String(parts[1]),
			}
		}

		volumes = append(volumes, &vol)
	}

	// Mount Points
	for _, mountPoint := range p.MountPoints {
		cleanedMountPoint := strings.Trim(mountPoint, " ")
		parts := strings.SplitN(cleanedMountPoint, " ", 3)

		ro, readOnlyBoolParseErr := strconv.ParseBool(parts[2])
		if readOnlyBoolParseErr != nil {
			readOnlyBoolWrappedErr := errors.New(readOnlyBoolBaseParseErr + readOnlyBoolParseErr.Error())
			fmt.Println(readOnlyBoolWrappedErr.Error())
			return readOnlyBoolWrappedErr
		}

		mpoint := ecs.MountPoint{
			SourceVolume:  aws.String(parts[0]),
			ContainerPath: aws.String(parts[1]),
			ReadOnly:      aws.Bool(ro),
		}
		definition.MountPoints = append(definition.MountPoints, &mpoint)
	}

	// Port mappings
	for _, portMapping := range p.PortMappings {
		cleanedPortMapping := strings.Trim(portMapping, " ")
		parts := strings.SplitN(cleanedPortMapping, " ", 2)
		hostPort, hostPortErr := strconv.ParseInt(parts[0], 10, 64)
		if hostPortErr != nil {
			hostPortWrappedErr := errors.New(hostPortBaseParseErr + hostPortErr.Error())
			fmt.Println(hostPortWrappedErr.Error())
			return hostPortWrappedErr
		}
		containerPort, containerPortErr := strconv.ParseInt(parts[1], 10, 64)
		if containerPortErr != nil {
			containerPortWrappedErr := errors.New(containerBaseParseErr + containerPortErr.Error())
			fmt.Println(containerPortWrappedErr.Error())
			return containerPortWrappedErr
		}

		pair := ecs.PortMapping{
			ContainerPort: aws.Int64(containerPort),
			HostPort:      aws.Int64(hostPort),
			Protocol:      aws.String("TransportProtocol"),
		}

		definition.PortMappings = append(definition.PortMappings, &pair)
	}

	// Environment variables
	for _, envVar := range p.Environment {
		parts := strings.SplitN(envVar, "=", 2)
		pair := ecs.KeyValuePair{
			Name:  aws.String(strings.Trim(parts[0], " ")),
			Value: aws.String(strings.Trim(parts[1], " ")),
		}
		definition.Environment = append(definition.Environment, &pair)
	}

	// Secret Environment variables
	for _, envVar := range p.SecretEnvironment {
		parts := strings.SplitN(envVar, "=", 2)
		pair := ecs.KeyValuePair{}
		if len(parts) == 2 {
			// set to custom named variable
			pair.SetName(aws.StringValue(aws.String(strings.Trim(parts[0], " "))))
			pair.SetValue(aws.StringValue(aws.String(os.Getenv(strings.Trim(parts[1], " ")))))
		} else if len(parts) == 1 {
			// default to named var
			pair.SetName(aws.StringValue(aws.String(parts[0])))
			pair.SetValue(aws.StringValue(aws.String(os.Getenv(parts[0]))))
		} else {
			fmt.Println("invalid syntax in secret enironment var", envVar)
		}
		definition.Environment = append(definition.Environment, &pair)
	}

	// Ulimits
	for _, uLimit := range p.Ulimits {
		cleanedULimit := strings.Trim(uLimit, " ")
		parts := strings.SplitN(cleanedULimit, " ", 3)
		name := strings.Trim(parts[0], " ")
		softLimit, softLimitErr := strconv.ParseInt(parts[1], 10, 64)
		if softLimitErr != nil {
			softLimitWrappedErr := errors.New(softLimitBaseParseErr + softLimitErr.Error())
			fmt.Println(softLimitWrappedErr.Error())
			return softLimitWrappedErr
		}
		hardLimit, hardLimitErr := strconv.ParseInt(parts[2], 10, 64)
		if hardLimitErr != nil {
			hardLimitWrappedErr := errors.New(hardLimitBaseParseErr + hardLimitErr.Error())
			fmt.Println(hardLimitWrappedErr.Error())
			return hardLimitWrappedErr
		}

		pair := ecs.Ulimit{
			Name:      aws.String(name),
			HardLimit: aws.Int64(hardLimit),
			SoftLimit: aws.Int64(softLimit),
		}

		definition.Ulimits = append(definition.Ulimits, &pair)
	}

	// DockerLabels
	for _, label := range p.Labels {
		parts := strings.SplitN(label, "=", 2)
		definition.DockerLabels[strings.Trim(parts[0], " ")] = aws.String(strings.Trim(parts[1], " "))
	}

	// EntryPoint
	for _, v := range p.EntryPoint {
		var command string
		command = v
		definition.EntryPoint = append(definition.EntryPoint, &command)
	}

	// LogOptions
	if len(p.LogDriver) > 0 {
		definition.LogConfiguration = new(ecs.LogConfiguration)
		definition.LogConfiguration.LogDriver = &p.LogDriver
		if len(p.LogOptions) > 0 {
			definition.LogConfiguration.Options = make(map[string]*string)
			for _, logOption := range p.LogOptions {
				parts := strings.SplitN(logOption, "=", 2)
				logOptionKey := strings.Trim(parts[0], " ")
				logOptionValue := aws.String(strings.Trim(parts[1], " "))
				definition.LogConfiguration.Options[logOptionKey] = logOptionValue
			}
		}
	}

	if len(p.NetworkMode) == 0 {
		p.NetworkMode = "bridge"
	}

	if len(p.HealthCheckCommand) != 0 {
		healthcheck := ecs.HealthCheck{
			Command:  aws.StringSlice(p.HealthCheckCommand),
			Interval: &p.HealthCheckInterval,
			Retries:  &p.HealthCheckRetries,
			Timeout:  &p.HealthCheckTimeout,
		}
		if p.HealthCheckStartPeriod != 0 {
			healthcheck.StartPeriod = &p.HealthCheckStartPeriod
		}
		definition.HealthCheck = &healthcheck
	}

	params := &ecs.RegisterTaskDefinitionInput{
		ContainerDefinitions: []*ecs.ContainerDefinition{
			&definition,
		},
		Family:      aws.String(p.Family),
		Volumes:     volumes,
		TaskRoleArn: aws.String(p.TaskRoleArn),
		NetworkMode: aws.String(p.NetworkMode),
	}

	cleanedCompatibilities := strings.Trim(p.Compatibilities, " ")
	compatibilitySlice := strings.Split(cleanedCompatibilities, " ")

	if cleanedCompatibilities != "" && len(compatibilitySlice) != 0 {
		params.RequiresCompatibilities = aws.StringSlice(compatibilitySlice)
	}

	if len(p.TaskCPU) != 0 {
		params.Cpu = aws.String(p.TaskCPU)
	}

	if len(p.TaskMemory) != 0 {
		params.Memory = aws.String(p.TaskMemory)
	}

	if len(p.TaskExecutionRoleArn) != 0 {
		params.ExecutionRoleArn = aws.String(p.TaskExecutionRoleArn)
	}

	resp, err := svc.RegisterTaskDefinition(params)
	if err != nil {
		return err
	}
	fmt.Println(resp)

	taskDefinitionArn := *(resp.TaskDefinition.TaskDefinitionArn)

	var taskDefinitionTags []*ecs.Tag
	for _, tag := range p.TaskDefinitionTags {
		parts := strings.SplitN(tag, "=", 2)
		key := parts[0]
		value := parts[1]
		fmt.Println(parts)
		fmt.Println(key)
		fmt.Println(value)
		taskDefinitionTags = append(taskDefinitionTags, &ecs.Tag{Key: aws.String(key), Value: aws.String(value)})
	}
	if len(taskDefinitionTags) != 0 {
		taskDefinitionTagsInput := &ecs.TagResourceInput{
			ResourceArn: aws.String(taskDefinitionArn),
			Tags:        taskDefinitionTags,
		}
		result, tagErr := svc.TagResource(taskDefinitionTagsInput)
		if tagErr != nil {
			return tagErr
		}
		fmt.Println(result)
	}
	sparams := &ecs.UpdateServiceInput{
		Cluster:              aws.String(p.Cluster),
		Service:              aws.String(p.Service),
		TaskDefinition:       aws.String(taskDefinitionArn),
		NetworkConfiguration: p.setupServiceNetworkConfiguration(),
	}
	if p.DesiredCount >= 0 {
		sparams.DesiredCount = aws.Int64(p.DesiredCount)
	}

	cleanedDeploymentConfiguration := strings.Trim(p.DeploymentConfiguration, " ")
	parts := strings.SplitN(cleanedDeploymentConfiguration, " ", 2)
	minimumHealthyPercent, minimumHealthyPercentError := strconv.ParseInt(parts[0], 10, 64)
	if minimumHealthyPercentError != nil {
		minimumHealthyPercentWrappedErr := errors.New(minimumHealthyPercentBaseParseErr + minimumHealthyPercentError.Error())
		fmt.Println(minimumHealthyPercentWrappedErr.Error())
		return minimumHealthyPercentWrappedErr
	}
	maximumPercent, maximumPercentErr := strconv.ParseInt(parts[1], 10, 64)
	if maximumPercentErr != nil {
		maximumPercentWrappedErr := errors.New(maximumPercentBaseParseErr + maximumPercentErr.Error())
		fmt.Println(maximumPercentWrappedErr.Error())
		return maximumPercentWrappedErr
	}

	sparams.DeploymentConfiguration = &ecs.DeploymentConfiguration{
		MaximumPercent:        aws.Int64(maximumPercent),
		MinimumHealthyPercent: aws.Int64(minimumHealthyPercent),
	}

	sresp, serr := svc.UpdateService(sparams)
	fmt.Println("update service input", sparams)
	if serr != nil {
		aerr, ok := serr.(awserr.Error)
		fmt.Println(ok)
		fmt.Println("update service error", aerr.Code(), aerr.Message(), aerr.Error())
		return serr
	} else {
		fmt.Println("update service successfully", sresp)
	}
	fmt.Println(sresp)
	fmt.Println("check task tag")
	var taskTags []*ecs.Tag
	for _, tag := range p.TaskTags {
		parts := strings.SplitN(tag, "=", 2)
		key := parts[0]
		value := parts[1]
		taskTags = append(taskTags, &ecs.Tag{Key: aws.String(key), Value: aws.String(value)})
	}
	fmt.Printf("task tags %#v\n", taskTags)
	if len(taskTags) == 0 {
		return nil
	}
	fmt.Println("wait 5s")
	time.Sleep(time.Duration(5) * time.Second)
	fmt.Println("begin tot list tasks")
	listTaskInput := &ecs.ListTasksInput{
		Cluster:     aws.String(p.Cluster),
		Family:      aws.String(p.Family),
		ServiceName: sresp.Service.ServiceName,
	}
	listTaskOutput, err := svc.ListTasks(listTaskInput)
	if err != nil {
		fmt.Println("fetch tasks error:", err.Error())
		return err
	}
	ans := listTaskOutput.TaskArns

	for listTaskOutput.NextToken != nil {
		fmt.Println("need fetch next page tasks,nexttoken = ", listTaskOutput.NextToken)
		listTaskInput.NextToken = listTaskOutput.NextToken
		listTaskOutput, err = svc.ListTasks(listTaskInput)
		if err != nil {
			fmt.Println("fetch tasks error:", err.Error())
		}else{
			ans  = append(ans,listTaskOutput.TaskArns...)
		}
	}
	for _, arn := range ans {
		taskTagsInput := &ecs.TagResourceInput{
			ResourceArn: arn,
			Tags:        taskTags,
		}
		fmt.Println("begin tag resource :", *arn)
		result, tagErr := svc.TagResource(taskTagsInput)
		if tagErr != nil {
			fmt.Println(tagErr.Error())
			return tagErr
		}
		fmt.Println(result)
	}

	scheduled_tasks_err := p.updateScheduledTasks(taskDefinitionArn)
	if scheduled_tasks_err != nil {
		fmt.Println("scheduled tasks error", scheduled_tasks_err)
		return scheduled_tasks_err
	}
	fmt.Println("new code!")
	return nil
}

// setupServiceNetworkConfiguration is used to setup the ECS service network
// configuration based on operator input.
func (p *Plugin) setupServiceNetworkConfiguration() *ecs.NetworkConfiguration {
	netConfig := ecs.NetworkConfiguration{AwsvpcConfiguration: &ecs.AwsVpcConfiguration{}}

	if p.NetworkMode != ecs.NetworkModeAwsvpc {
		return nil
	}

	if len(p.ServiceNetworkAssignPublicIp) != 0 {
		netConfig.AwsvpcConfiguration.SetAssignPublicIp(p.ServiceNetworkAssignPublicIp)
	}

	if len(p.ServiceNetworkSubnets) > 0 {
		netConfig.AwsvpcConfiguration.SetSubnets(aws.StringSlice(p.ServiceNetworkSubnets))
	}

	if len(p.ServiceNetworkSecurityGroups) > 0 {
		netConfig.AwsvpcConfiguration.SetSecurityGroups(aws.StringSlice(p.ServiceNetworkSecurityGroups))
	}

	return &netConfig
}

func (p *Plugin) setupScheduledTaskServiceNetworkConfiguration(assignPublicIp string, subnets []string, securityGroups []string) *cloudwatchevents.NetworkConfiguration {
	netConfig := cloudwatchevents.NetworkConfiguration{AwsvpcConfiguration: &cloudwatchevents.AwsVpcConfiguration{}}

	if p.NetworkMode != ecs.NetworkModeAwsvpc {
		return nil
	}
	if len(assignPublicIp) != 0 {
		netConfig.AwsvpcConfiguration.SetAssignPublicIp(assignPublicIp)
	}

	if len(subnets) > 0 {
		netConfig.AwsvpcConfiguration.SetSubnets(aws.StringSlice(subnets))
	}

	if len(securityGroups) > 0 {
		netConfig.AwsvpcConfiguration.SetSecurityGroups(aws.StringSlice(securityGroups))
	}

	return &netConfig
}

func (p *Plugin) updateScheduledTasks(taskDefinitionArn string) error {
	scheduledTasks := p.ScheduledTasks
	if len(scheduledTasks) == 0 {
		return nil
	}
	var tasks []CloudWatchEventRuleAndTargets
	err := json.Unmarshal([]byte(scheduledTasks), &tasks)
	if err != nil {
		fmt.Println("parse scheduled tasks configuration error", err)
		return err
	}
	if len(tasks) == 0 {
		return nil
	}

	awsConfig := aws.Config{}
	if len(p.Key) != 0 && len(p.Secret) != 0 {
		awsConfig.Credentials = credentials.NewStaticCredentials(p.Key, p.Secret, "")
	}
	awsConfig.Region = aws.String(p.Region)
	cloudWatchEventService := cloudwatchevents.New(session.New(&awsConfig))

	for _, t := range tasks {
		rule := t.Rule
		targets := t.Targets
		putRuleInput := cloudwatchevents.PutRuleInput{
			Name:               aws.String(rule.Name),
			ScheduleExpression: aws.String(rule.ScheduledExpression),
		}
		if len(rule.Description) != 0 {
			putRuleInput.Description = aws.String(rule.Description)
		}
		fmt.Println("put rule", putRuleInput)
		putRuleResult, err := cloudWatchEventService.PutRule(&putRuleInput)
		if err != nil {
			fmt.Println("put rule error", err)
			return err
		} else {
			fmt.Println("put rule successfully", putRuleResult)
		}
		var ruleTargets []*cloudwatchevents.Target
		for _, target := range targets {
			// networkConfiguration := p.setupScheduledTaskServiceNetworkConfiguration(
			// 	target.NetworkAssignPublicIP,
			// 	target.NetworkSubnets,
			// 	target.NetworkSecurityGroups)
			ecsParameters := cloudwatchevents.EcsParameters{
				LaunchType:        aws.String(target.LaunchType),
				TaskCount:         aws.Int64(target.TaskCount),
				TaskDefinitionArn: aws.String(taskDefinitionArn),
			}
			if (len(target.NetworkAssignPublicIP) != 0) || (len(target.NetworkSubnets) != 0 || len(target.NetworkSecurityGroups) != 0) {
				ecsParameters.NetworkConfiguration = p.setupScheduledTaskServiceNetworkConfiguration(
					target.NetworkAssignPublicIP,
					target.NetworkSubnets,
					target.NetworkSecurityGroups)
			}
			if len(target.Group) != 0 {
				ecsParameters.Group = aws.String(target.Group)
			}
			if strings.ToUpper(target.LaunchType) == ecs.LaunchTypeFargate {
				if len(target.PlatformVersion) != 0 {
					ecsParameters.PlatformVersion = aws.String(target.PlatformVersion)
				} else {
					ecsParameters.PlatformVersion = aws.String("LATEST")
				}
			}
			t := cloudwatchevents.Target{
				Arn:           aws.String(target.ClusterArn),
				Id:            aws.String(target.Id),
				RoleArn:       aws.String(target.RoleArn),
				Input:         aws.String(target.Input),
				EcsParameters: &ecsParameters,
			}
			ruleTargets = append(ruleTargets, &t)
		}
		putTargetsInput := cloudwatchevents.PutTargetsInput{
			Rule:    aws.String(rule.Name),
			Targets: ruleTargets,
		}
		fmt.Println("put targets to rule", putTargetsInput)
		putTargetsResult, err := cloudWatchEventService.PutTargets(&putTargetsInput)
		if err != nil {
			fmt.Println("put targets error", err)
			return err
		} else {
			fmt.Println("put targets successfully", putTargetsResult)
		}
	}
	return nil
}
