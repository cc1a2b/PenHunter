package cli

import (
	"fmt"
	"penhunter/utils"
)

func ShowBanner() {
	banner := `
    ____             __  __            __           
   ╱ __ ╲___  ____  ╱ ╱ ╱ ╱_  ______  ╱ ╱____  _____
  ╱ ╱_╱ ╱ _ ╲╱ __ ╲╱ ╱_╱ ╱ ╱ ╱ ╱ __ ╲╱ __╱ _ ╲╱ ___╱
 ╱ ____╱  __╱ ╱ ╱ ╱ __  ╱ ╱_╱ ╱ ╱ ╱ ╱ ╱_╱  __╱ ╱    
╱_╱    ╲___╱_╱ ╱_╱_╱ ╱_╱╲__,_╱_╱ ╱_╱╲__╱╲___╱_╱     
                                                    

Created by cc1a2b (•ˋ_ˊ•)               v0.1`
	fmt.Printf("%s%s%s\n", utils.Red, banner, utils.NC)
}

func ShowBannerColored(color string) {
	banner := `
    ____             __  __            __           
   ╱ __ ╲___  ____  ╱ ╱ ╱ ╱_  ______  ╱ ╱____  _____
  ╱ ╱_╱ ╱ _ ╲╱ __ ╲╱ ╱_╱ ╱ ╱ ╱ ╱ __ ╲╱ __╱ _ ╲╱ ___╱
 ╱ ____╱  __╱ ╱ ╱ ╱ __  ╱ ╱_╱ ╱ ╱ ╱ ╱ ╱_╱  __╱ ╱    
╱_╱    ╲___╱_╱ ╱_╱_╱ ╱_╱╲__,_╱_╱ ╱_╱╲__╱╲___╱_╱     
                                                    

Created by cc1a2b (•ˋ_ˊ•)               v0.1`
	fmt.Printf("%s%s%s\n", color, banner, utils.NC)
}
