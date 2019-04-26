properties([[$class: 'jenkins.model.BuildDiscarderProperty', strategy:
            [$class: 'LogRotator', numToKeepStr: '100', artifactNumToKeepStr: '20']
            ]])
            
pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                echo "Building branch: ${env.BRANCH_NAME}"
                sh "git lfs install"
                sh "./gradlew pack -x test" 
            }
        }
        
        stage('Archive build output') {
            when {
                expression { 
                    GIT_BRANCH == 'master' ||
                        GIT_BRANCH == 'master-pre-merge' 
                }
            }

            steps {                
                archiveArtifacts artifacts: 'pack/aion-v*.tar.bz2'
            }
        }

        stage('Functional tests') { 
            steps { 
                    dir('FunctionalTests') {
                        git url: 'https://github.com/aionnetwork/node_test_harness.git', branch: 'master-debug' 
                    }

                    sh('cp pack/aion.tar.bz2 FunctionalTests/Tests')

                    dir('FunctionalTests') { 
                        sh('tar -C Tests -xjf Tests/aion.tar.bz2')
                        sh('./gradlew :Tests:ciTest -i')
                    }

            }
        }
    }

    post {
        always {
            sh('([ -d FunctionalTests ] && cp -r FunctionalTests/report/FunctionalTests report/) || true')
            junit "report/**/*.xml"
            cleanWs()
    }

    success {
        slackSend channel: '#ci',
            color: 'good',
            message: "The pipeline ${currentBuild.fullDisplayName} completed successfully. Grab the generated builds at ${env.BUILD_URL}"
    } 

        failure {
            slackSend channel: '#ci',
                    color: 'danger', 
                    message: "The pipeline ${currentBuild.fullDisplayName} failed at ${env.BUILD_URL}"
        }

    }
}

environment {
    JAVA_HOME = "${env.JDK_9_HOME}"
    ANT_HOME = "${env.ANT_HOME}"
    SYSTEM_TESTS_HOME = "test"
    GIT_BRANCH = "${env.BRANCH_NAME}"
    DOCKER_HOST = "unix:///var/run/docker.sock"
}
