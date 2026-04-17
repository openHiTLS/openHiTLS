# openHiTLS社区贡献攻略

### 1.注册GitCode

openHiTLS社区项目源代码托管在GitCode上。  
请参考[https://docs.gitcode.com/docs/start/quick](https://docs.gitcode.com/docs/start/quick)注册您的GitCode账户，并在[https://gitcode.com/setting/email](https://gitcode.com/setting/email)设置您的主邮箱。

### 2.签署CLA

在参与社区贡献前，您需要根据自身的参与身份（个人、员工、企业），提前签署 [openHiTLS社区贡献者许可协议（CLA）](https://cla.openhitls.net/) 。

* 个人 CLA：以个人身份参与社区，请签署个人 CLA。
* 企业 CLA：以企业管理员的身份参与社区，请签署法人CLA。
* 员工 CLA：以企业员工的身份参与社区，请签署法人贡献者 CLA（需先完成法人CLA签署）。

参考资料：

* \[1\][企业及其员工签署openHiTLS贡献者许可协议（CLA）指导](https://www.openhitls.net/zh/blogs/claSign/enterpriseAndEmployeeSignCla.html)

### 3.CLA参与社区贡献

在签署了CLA 协议之后，就可以开始您的社区贡献之旅啦。当然，为维护社区的友好开发和协作环境，在参与社区贡献之前，请先阅读并遵守[openHiTLS 社区的行为守则](https://www.openhitls.net/zh/community/codes-conduct.html) 以及 [openHiTLS社区开发行为规范](https://gitcode.com/openHiTLS/community/blob/main/contributors/CODE-OF-CONDUCT-zh.md)。

### 3.1 提交Issue

#### 3.1.1 找到愿意处理的Issue

在您感兴趣的工作组项目GitCode主页内，单击“Issues”，您可以找到其[Issue列表](https://gitcode.com/openHiTLS/openhitls/issues/)。如果您愿意处理其中的一个Issue，可以在Issue评论区积极评论，管理员将为您分配Issue。请您及时处理分配的Issue，若处理不及时，管理员可能会将Issue重新分配给其他人。或者您也可以在对应的团队或项目的repository内，进入Issue面板“新建Issue”。

#### 3.1.2 新创建Issue 

如果您准备向社区上报Bug或者提交需求，或者为openHiTLS社区贡献自己的意见或建议，请在社区对应的仓库上提交Issue（可访问[Issue](https://gitcode.com/openHiTLS/openhitls/issues/)）。

新建Issue：

 1. 进入Issue面板，单击“新建Issue”。

 2. 单选下拉框将Issue类型设置成“需求”，系统会自动为您调出需求模板。

 3. 标题栏简要描述需求的要点。

 4. 在详细说明框内说明需求的场景和价值。

#### 3.1.3 提交PR前Issue内的充分讨论 

对于您领取到的Issue任务或想发起一个大的贡献，建议在开始代码工作之前，发起一个Issue讨论，并在每个Issue下面与社区Maintainer、Committer等核心开发者充分讨论方案思路，提供相应设计思路文档等。社区轮值Maintainer将在**2**个工作日内对最新的讨论做出回复或分配给相关领域专家答复。

### 3.2 提交Pull-Request 

#### 3.2.1 了解工作组和项目内的开发注意事项 
每个工作组内的项目使用的编码语言、开发环境、编码约定等都可能存在差异的。如果您想了解并参与到编码类贡献，应遵守[编码安全规范](https://gitcode.com/openHiTLS/community/tree/main/contributors/CODING-SECURITY-RULES-zh.md)和[代码风格规范](https://gitcode.com/openHiTLS/community/tree/main/contributors/CODING-STYLE-GUIDE-zh.md)。

#### 3.2.2 下载代码和拉分支 

如果要参与代码贡献，您还需要了解如何在GitCode下载代码，通过PR合入代码等，具体使用请参见[《Fork工作流》](https://docs.gitcode.com/docs/help/home/org_project/pullrequests/pr-fork)。该托管平台的使用方法类似GitHub，如果您以前使用过GitHub，本节的内容您可以大致了解。

#### 3.2.3 修改、构建和本地验证 

在本地分支上完成修改后，进行构建和本地验证。

#### 3.2.4 提交一个Pull-Request

当您准备提交一个PR的时候，就意味您已经准备开始给社区贡献代码了（可访问[Pull Requests](https://gitcode.com/openHiTLS/openhitls/pulls)）。为了使您的提交更容易被接受，您需要：

* 准备完善的提交信息（应遵[commit信息书写规范](https://gitcode.com/openHiTLS/community/tree/main/contributors/COMMIT-MESSAGE-CONVENTIONS-zh.md)）。
* 如果一次提交的代码量较大，建议将大型的内容分解成一系列逻辑上较小的内容，分别进行提交会更便于检视者理解您的想法。
* 在提交开发代码，特别是特性开发代码的同时，提倡同步提交测试case代码，保证开发和测试的同步。
* **为提升社区maintainer、committer的评审效率，请先确保提交PR代码流水线检查通过（未通过流水线检查的PR，将不会进入到代码审核环节）。**

### 3.3 检视代码

openHiTLS开源社区是一个开放的社区，我们希望所有参与社区的人都能成为活跃的检视者。当成为工作组的committer或maintainer角色时，便拥有审核代码的责任与权利。

[《补丁审核的柔和艺术》](https://sage.thesharps.us/2014/09/01/the-gentle-art-of-patch-review/)一文中提出了一系列检视的重点，说明代码检视的活动也希望能够促进新的贡献者积极参与，而不会使贡献者一开始就被细微的错误淹没，所以检视的时候，可以重点关注包括：

* 贡献背后的想法是否合理。
* 贡献的架构是否正确。
* 贡献是否完善。

## 5\. 和社区一起成长

社区不同角色对应不同的责任与权利，每种角色都是社区不可或缺的一部分，您可以通过积极贡献不断积累经验和影响力，并获得角色上的成长。请查看[社区章程说明](https://www.openhitls.net/zh/community/charter.html)了解更详细介绍与责任权利描述。