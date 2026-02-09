package main

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

func areSlicesEqualUnordered(slice1, slice2 []string) bool {
	// 如果长度不同，直接返回 false
	if len(slice1) != len(slice2) {
		return false
	}

	// 用 map 统计 slice1 中元素出现次数
	count := make(map[string]int)
	for _, item := range slice1 {
		count[item]++
	}

	// 检查 slice2 中的元素
	for _, item := range slice2 {
		count[item]--
		if count[item] < 0 {
			return false // 如果出现负数，说明 slice2 中有 slice1 没有的元素
		}
	}

	// 检查是否所有计数都为 0
	for _, v := range count {
		if v != 0 {
			return false // 如果有非 0 值，说明元素数量不匹配
		}
	}

	return true
}

func contains(sliceA, sliceB []string) bool {
	// 如果 B 的长度大于 A，直接返回 false
	if len(sliceB) > len(sliceA) {
		return false
	}

	// 将 sliceA 的元素存入 map
	setA := make(map[string]bool)
	for _, item := range sliceA {
		setA[item] = true
	}

	// 检查 sliceB 的每个元素是否在 setA 中
	for _, item := range sliceB {
		if !setA[item] {
			return false // 如果有一个元素不在 A 中，返回 false
		}
	}

	return true
}

func areCnameContains(sliceA, sliceB []string) bool {
	return contains(sliceA, sliceB) || contains(sliceA, sliceB)
}

func (bC *BindCache) nsDiffers() {
	tasks := make(chan string, 100)
	buffer := new(bytes.Buffer)
	x := 0
	NSDomains := make(map[string][]string)
	for domain, record := range bC.records {
		if len(record.NSs) != 0 {
			var nss []string
			for _, ns := range record.NSs {
				nss = append(nss, ns.NsDomain)
			}
			NSDomains[domain] = nss
		}
	}

	// 分发扫描任务
	go func() {
		for domain, _ := range NSDomains {
			tasks <- domain
		}
		close(tasks)
	}()

	// 启动 worker Goroutine
	var wg sync.WaitGroup

	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for domain := range tasks {

				//NS不一致

				// 获取标准DNS解析地址和实际结果比较
				expectedDnsServer := "112.4.0.55"

				expectedResult, err := getDNSStatus(domain, expectedDnsServer)
				num := 0
				for err != nil && num < 1 {
					expectedResult, err = getDNSStatus(domain, expectedDnsServer)
					num++
				}

				var output []string
				isExpected := true

				for _, ns := range NSDomains[domain] {
					actualResult, _ := getDNSStatus(domain, ns)

					//处理cname链，最大深度为5
					digCnameCount := 0
					for len(actualResult.RR_CNAME) > 0 && digCnameCount < 5 {
						digCnameCount++
						actualResult, _ = getDNSStatus(actualResult.RR_CNAME[0], ns)
					}

					// 检查A记录和CNAME是否一致
					aDiffers := !areSlicesEqualUnordered(expectedResult.RR_A, actualResult.RR_A)
					//cnameNotContained := !areCnameContains(expectedResult.RR_CNAME, actualResult.RR_CNAME)

					//if aDiffers && cnameNotContained {
					if aDiffers {
						sort.Strings(actualResult.RR_A)
						output = append(output, fmt.Sprintf("%*sns（%s）结果-%s-%s",
							len(domain)+10, " ", ns, actualResult.RR_A, actualResult.RR_CNAME))
						isExpected = false
					}
				}

				if !isExpected {
					fmt.Println(fmt.Sprintf("%s NS不一致：ns（%s）结果-%s-%s\n%s\n\n",
						domain,
						expectedDnsServer,
						expectedResult.RR_A,
						expectedResult.RR_CNAME,
						strings.Join(output, "\n")))
					buffer.WriteString(fmt.Sprintf("%s NS不一致：ns（%s）结果-%s-%s\n%s\n\n",
						domain,
						expectedDnsServer,
						expectedResult.RR_A,
						expectedResult.RR_CNAME,
						strings.Join(output, "\n")))
				}
				x++

				fmt.Printf("%d/%d\n", x, len(NSDomains))

			}
		}()
	}

	wg.Wait()

	file, err := os.Create("ns.txt")
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()

	buffer.WriteTo(file)
}
