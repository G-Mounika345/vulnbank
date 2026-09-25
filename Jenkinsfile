pipeline {
    agent any

    environment {
        DC_DATA_DIR = 'C:/Tools/dependency-check-12.1.0-release/dependency-check/data'
        REPORT_DIR  = 'sca-reports'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Build') {
            steps {
                dir('vulnbank') {
                    bat 'mvn -q -DskipTests compile'
                }
            }
        }

        stage('SCA - OWASP Dependency-Check') {
            steps {
                dir('vulnbank') {
                    withCredentials([string(credentialsId: 'nvd-api-key', variable: 'NVD_API_KEY')]) {
                        script {
                            bat "if not exist ${REPORT_DIR}\\dependency-check mkdir ${REPORT_DIR}\\dependency-check"
                            // Uses the Maven plugin (not the standalone CLI) so it reads the
                            // dependency graph Maven already resolved, instead of fingerprinting
                            // whatever jars happen to sit on disk.
                            //
                            // NOTE: -DoutputDirectory does not relocate the plugin's output in
                            // practice (confirmed on build #5 - it still wrote to target/ despite
                            // the flag), so we let it write to its real default (target/) and copy
                            // the reports out afterwards instead of fighting that.
                            def status = bat(
                                returnStatus: true,
                                script: "mvn org.owasp:dependency-check-maven:12.1.0:check -DprojectName=VulnBank -Dformat=ALL -DdataDirectory=\"%DC_DATA_DIR%\" -DnvdApiKey=%NVD_API_KEY% -DfailBuildOnCVSS=11 -DossindexAnalyzerEnabled=false"
                            )
                            bat "copy /Y target\\dependency-check-report.* ${REPORT_DIR}\\dependency-check\\ >nul"
                            if (status != 0) {
                                unstable("Dependency-Check exited with status ${status}")
                            }
                        }
                    }
                }
            }
        }

        stage('SCA - Snyk') {
            steps {
                dir('vulnbank') {
                    script {
                        try {
                            withCredentials([string(credentialsId: 'snyk-token', variable: 'SNYK_TOKEN')]) {
                                bat "mkdir ${REPORT_DIR}\\snyk 2>nul & exit 0"
                                bat "snyk auth %SNYK_TOKEN%"
                                def status = bat(
                                    returnStatus: true,
                                    script: "snyk test --json-file-output=${REPORT_DIR}\\snyk\\snyk-report.json"
                                )
                                bat "snyk-to-html -i ${REPORT_DIR}\\snyk\\snyk-report.json -o ${REPORT_DIR}\\snyk\\snyk-report.html"
                                if (status != 0) {
                                    unstable("Snyk found vulnerabilities (exit ${status})")
                                }
                            }
                        } catch (org.jenkinsci.plugins.credentialsbinding.impl.CredentialNotFoundException e) {
                            echo "Skipping Snyk stage: 'snyk-token' credential not configured yet."
                            unstable("Snyk stage skipped - no token configured")
                        }
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'vulnbank/sca-reports/**', fingerprint: true, allowEmptyArchive: true
            script {
                if (fileExists('vulnbank/sca-reports/dependency-check/dependency-check-report.html')) {
                    publishHTML(target: [
                        reportDir: 'vulnbank/sca-reports/dependency-check',
                        reportFiles: 'dependency-check-report.html',
                        reportName: 'Dependency-Check Report',
                        alwaysLinkToLastBuild: true,
                        keepAll: true
                    ])
                } else {
                    echo 'No Dependency-Check report found - skipping publishHTML.'
                }
                if (fileExists('vulnbank/sca-reports/snyk/snyk-report.html')) {
                    publishHTML(target: [
                        reportDir: 'vulnbank/sca-reports/snyk',
                        reportFiles: 'snyk-report.html',
                        reportName: 'Snyk Report',
                        alwaysLinkToLastBuild: true,
                        keepAll: true
                    ])
                } else {
                    echo 'No Snyk report found - skipping publishHTML.'
                }
            }
        }
    }
}
